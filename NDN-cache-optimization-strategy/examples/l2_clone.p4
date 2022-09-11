#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct headers {
    ethernet_t ethernet;
}

struct metadata {
    bit<14> ecmp_select;
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

parser ParserImpl(packet_in pkt, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control DeparserImpl(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action l2_forword(bit<9> port) {
        standard_metadata.bit_mcast=0x7fffffff;
        standard_metadata.egress_port = port;
    }
    table ether_exact {
        actions = {
            l2_forword;
            _drop;
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        default_action = _drop();
    }
    apply {
        if (hdr.ethernet.isValid()) {
            ether_exact.apply();
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

