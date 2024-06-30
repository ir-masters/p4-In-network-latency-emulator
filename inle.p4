/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* Define constants for types of packets */
#define PKT_INSTANCE_TYPE_NORMAL 0

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_TCP = 0x06;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> tcpPort_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    tcpPort_t srcPort;
    tcpPort_t dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header hop_latency_t {
    bit<48> hopLatency;
}

const bit<8> RECIRC_FL_1 = 1;

struct metadata {
    @field_list(RECIRC_FL_1)
    bit<48> hopLatency;
    bit<48> arrivalTimestamp;
    bit<48> departureTimestamp;
    bit<48> initialArrivalTimestamp; // Preserve initial arrival timestamp
    bit<8> recircCounter;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    hop_latency_t hop_latency;
}

/*************************************************************************
*********************** P A R S E R  *************************************
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
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition parse_hop_latency;
    }

    state parse_hop_latency {
        packet.extract(hdr.hop_latency);
        // Only set initialArrivalTimestamp if it's zero (i.e., first arrival)
        if (meta.initialArrivalTimestamp == 0) {
            meta.initialArrivalTimestamp = standard_metadata.ingress_global_timestamp;
        }
        meta.arrivalTimestamp = standard_metadata.ingress_global_timestamp;
        meta.hopLatency = hdr.hop_latency.hopLatency;
        meta.departureTimestamp = meta.initialArrivalTimestamp + meta.hopLatency;
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

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // Define the output port
        standard_metadata.egress_spec = port;
        // Update src and dst MACs according to the current switch
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        // Decrease TTL by one when forwarding the packet
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action recirculate_packet() {
        // Increase recirculation counter
        meta.recircCounter = meta.recircCounter + 1;
        // update header fields
        meta.departureTimestamp = standard_metadata.ingress_global_timestamp + meta.hopLatency;
        // Send the packet through the ingress pipeline again
        resubmit_preserving_field_list(RECIRC_FL_1);
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

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_forward_table.apply();
        }

        // Recirculate the packet if departure time is not reached and recircCounter < MAX_RECIRC
        if (meta.departureTimestamp > standard_metadata.ingress_global_timestamp && meta.recircCounter < 5) {
            recirculate_packet();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // No specific egress logic needed
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
        packet.emit(hdr.ipv4);        // Always emit ipv4 if valid
        packet.emit(hdr.tcp);         // Always emit tcp if valid
        packet.emit(hdr.hop_latency); // Always emit hop latency
    }
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
