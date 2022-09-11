#include <core.p4>
#define V1MODEL_VERSION 20200914
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header geo_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_length;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    geo_t      geo;
    ipv6_t     ipv6;
}

struct metadata_t {
    bit<14> ecmp_select;
}

control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply {
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata_t meta) {
    apply {
    }
}

parser MyParser(packet_in pkt, out headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    @name(".start") state start {
        transition parse_ethernet;
    }
    @name(".parse_ethernet") state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x86dd : parse_ipv6;
            default: accept;
        }
    }
    @name(".parse_ipv6") state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition accept;
    }
}

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

control MyIngress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv6_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_port = port;
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }
    table ipv6_exact {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            ipv6_forward;
            _drop;
        }
        default_action = _drop();
    }
    apply {
        if (hdr.ipv6.isValid()) {
            if (ipv6_exact.apply().miss){
                _drop();
            }
        } else{
            _drop();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;


