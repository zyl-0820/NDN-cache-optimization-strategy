#include <core.p4>
#include <v1model.p4>


const bit<16> IP=0x800;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/* 
header vlan_t {
    bit<3>  typeID;
    bit<1>  cfi;
    bit<6>  inPort;
    bit<6>  outPort;
    bit<16> etherType;
}
*/

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
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4")
    ipv4_t       ipv4;
    //@name(".vlan")
    //vlan_t       vlan;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
//        transition accept;
        transition select(hdr.ethernet.etherType) {
           0x0800: parse_ipv4;
            default: reject;
        }
    }
   @name(".parse_ipv4")  state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
   // @name(".parse_vlan")  state parse_vlan {
     //   packet.extract(hdr.vlan);
       // transition select(hdr.vlan.etherType) {
         //    0x0800: parse_ipv4;
           //  }
       // }

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
    @name(".reg1")register<bit<32>>(1) reg1;
    @name(".var1")bit<32> var1;
    @name(".forward") action forward(bit<9> port) {
        standard_metadata.egress_port = port;
        reg1.read(var1,0);
        hdr.ethernet.srcAddr=hdr.ethernet.dstAddr;
        standard_metadata.egress_port = (bit<9>)var1;
    }
    
    @name(".bcast") action bcast() {
        standard_metadata.egress_port = 9w100;
        hdr.ethernet.dstAddr=hdr.ethernet.srcAddr;
    }
    @name(".mac_learn") action mac_learn() {
        digest<mac_learn_digest>((bit<32>)1024, { hdr.ethernet.srcAddr, standard_metadata.ingress_port });
    }


    @name("._nop") action _nop() {
    }
    @name(".dmac") table dmac {
        actions = {
            forward;
            bcast;
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        size = 512;
        default_action=bcast();
    }
    @name(".smac") table smac {
        actions = {
            mac_learn;
            _nop;
        }
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        size = 512;
    }
    apply {
        smac.apply();
        dmac.apply();
        if(hdr.ipv4.isValid())
        {

            @atomic {
            reg1.read(var1,0);
            var1 = var1 + 1;
            reg1.write(0, var1);
            hdr.ipv4.dstAddr = var1;
//            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr; 
            //hdr.vlan.outPort = 6w1;
            standard_metadata.egress_port = 9w1;
        }

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

