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
            0x080a: parse_geo;
            default: accept;
        }
    }
    @name(".parse_geo") state parse_geo {
        pkt.extract(hdr.geo);
        transition accept;
    }
}

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.geo);
    }
}

control MyIngress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action geo_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        // hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.geo.ttl = hdr.geo.ttl - 1;
    }
    table geo_ternary {
        key = {
            hdr.geo.dstAddr: ternary;
        }
        actions = {
            geo_forward;
            _drop;
            NoAction;
        }
        default_action = _drop();
    }
    apply {
        if (hdr.geo.isValid()) {
            if(geo_ternary.apply().miss){
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


