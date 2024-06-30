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

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

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

header customdata_t {
    bit<16> proto_id;
    bit<16> content_id;
    bit<16> ingress_num;
    bit<8>  egress_num;
    bit<48> hop_latency; // hop_latency in seconds
    bit<48> arrival_time;
    bit<48> departure_time;
}

const bit<8> RECIRC_FL_1 = 3;
const bit<16> MAX_RECIRC = 1000;

struct resubmit_meta_t {
    @field_list(RECIRC_FL_1)
    bit<16> i;
    bit<48> arrival_timestamp;
    bit<48> departure_timestamp;
}

struct metadata {
    resubmit_meta_t resubmit_meta;
}

struct headers {
    ethernet_t      ethernet;
    customdata_t    customdata;
    ipv4_t          ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

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
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action update_customdata_processing_count_by_num(in bit<16> ingress_num) {
        hdr.customdata.ingress_num = hdr.customdata.ingress_num + ingress_num;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action customdata_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action recirculate_packet() {
        resubmit_preserving_field_list(RECIRC_FL_1);
    }

    action timestamp_packet() {
        hdr.customdata.arrival_time = standard_metadata.ingress_global_timestamp;
        meta.resubmit_meta.arrival_timestamp = hdr.customdata.arrival_time;
    }

    action calculate_departure_time(bit<48> latency_ns) {
        hdr.customdata.departure_time = standard_metadata.ingress_global_timestamp + latency_ns;
        meta.resubmit_meta.departure_timestamp = hdr.customdata.departure_time;
    }

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
            if (hdr.customdata.departure_time > standard_metadata.ingress_global_timestamp) {
                if (meta.resubmit_meta.i < MAX_RECIRC) {
                    meta.resubmit_meta.i  = meta.resubmit_meta.i + 1;
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
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action update_customdata_processing_count_by_num(in bit<8> egress_num) {
        hdr.customdata.egress_num = hdr.customdata.egress_num + egress_num;
    }

    action update_arrival_time() {
        hdr.customdata.arrival_time = meta.resubmit_meta.arrival_timestamp;
    }

    action update_departure_time() {
        hdr.customdata.departure_time = meta.resubmit_meta.departure_timestamp;
    }

    apply {
        if (hdr.customdata.isValid()) {
            update_customdata_processing_count_by_num(1);
            update_arrival_time();
            update_departure_time();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

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
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.customdata);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
