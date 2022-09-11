#include <core.p4>
#include <v1model.p4>


const bit<16> IP=0x800;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct metadata {
    bit<32> pkg_number;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4")
    ipv4_t       ipv4;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
//        transition accept;
        transition select(hdr.ethernet.etherType) {
           0x800: parse_ipv4;
            default: reject;
        }
    }
   @name(".parse_ipv4")  state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

@name("mac_learn_digest") struct mac_learn_digest {
    bit<48> srcAddr;
    bit<9>  ingress_port;
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<32>>(1) reg1;
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_static() {

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        reg1.read(meta.pkg_number, 0);
        meta.pkg_number = 1 + meta.pkg_number;
        reg1.write(0, meta.pkg_number);
        hdr.ipv4.dstAddr = meta.pkg_number;
        standard_metadata.egress_spec = 9w1;
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_static;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    apply {
        if(hdr.ipv4.isValid())
        {
            if(ipv4_lpm.apply().miss){
                drop();
            }
        }else{
            drop();
        }


    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

