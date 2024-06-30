/* -*- P4_16 -*- */
/* BMv2 */
#include <core.p4>
#include <v1model.p4>

/* Define constants for types of packets */
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_CUSTOMDATA = 0x1313;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* Define the Ethernet header */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/* Define the IPv4 header */
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* Define the custom data header for latency emulation */
header customdata_t {
    bit<16> proto_id;
    bit<16> content_id;
    bit<16> ingress_num;
    bit<8>  egress_num;
    bit<48> hop_latency;
    
}

const bit<8> RECIRC_FL_1 = 1;
const bit<16> MAX_RECIRC = 100000;

/* Metadata structure for resubmitting packets */
struct resubmit_meta_t {
    @field_list(RECIRC_FL_1)
    bit<16> i;
    @field_list(RECIRC_FL_1)
    bit<48> arrival_time;
    @field_list(RECIRC_FL_1)
    bit<48> departure_time;
}

/* Define the metadata structure */
struct metadata {
    resubmit_meta_t resubmit_meta;
}

/* Define the headers structure */
struct headers {
    ethernet_t      ethernet;
    customdata_t    customdata;
    ipv4_t          ipv4;
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

/* Define the parser */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_CUSTOMDATA: parse_customdata;
            default: accept;
        }
    }

    state parse_customdata {
        packet.extract(hdr.customdata);
        transition select(hdr.customdata.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   **************
*************************************************************************/

/* Checksum verification control block */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

/* Define the ingress processing control block */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Drop action */
    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* Update custom data processing count */
    action update_customdata_processing_count_by_num(in bit<16> ingress_num) {
        hdr.customdata.ingress_num = hdr.customdata.ingress_num + ingress_num;
    }

    /* IPv4 forwarding action */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* Custom data forwarding action */
    action customdata_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    /* Recirculate packet action */
    action recirculate_packet() {
        resubmit_preserving_field_list(RECIRC_FL_1);
    }

    /* Timestamp packet arrival */
    action timestamp_packet() {
        meta.resubmit_meta.arrival_time = standard_metadata.ingress_global_timestamp;
    }

    /* Calculate departure time */
    action calculate_departure_time(bit<48> latency) {
        meta.resubmit_meta.departure_time = meta.resubmit_meta.arrival_time + latency;
    }

    /* Table for IPv4 forwarding */
    table ipv4_forward_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    /* Table for custom data forwarding */
    table customdata_forward_table {
        key = {
            hdr.customdata.content_id: exact;
        }
        actions = {
            customdata_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.customdata.isValid()) {
            if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_INGRESS_RECIRC) {
                timestamp_packet();
                calculate_departure_time(hdr.customdata.hop_latency);
                update_customdata_processing_count_by_num(meta.resubmit_meta.i);
            }
            if (meta.resubmit_meta.departure_time > standard_metadata.ingress_global_timestamp) {
                if (meta.resubmit_meta.i < MAX_RECIRC) {
                    meta.resubmit_meta.i = meta.resubmit_meta.i + 1;
                    recirculate_packet();
                }
            }
            update_customdata_processing_count_by_num(1);
            customdata_forward_table.apply();
        }

        if (hdr.ipv4.isValid() && !hdr.customdata.isValid()) {
            ipv4_forward_table.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

/* Define the egress processing control block */
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    /* Update custom data processing count */
    action update_customdata_processing_count_by_num(in bit<8> egress_num) {
        hdr.customdata.egress_num = hdr.customdata.egress_num + egress_num;
    }

    apply {
        if (hdr.customdata.isValid()) {
            update_customdata_processing_count_by_num(1);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

/* Checksum computation control block */
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  ********************************
*************************************************************************/

/* Define the deparser */
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.customdata);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

/* Define the main switch */
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
