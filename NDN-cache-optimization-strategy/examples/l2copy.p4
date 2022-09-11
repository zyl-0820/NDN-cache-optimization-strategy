#include <core.p4>
#include <v1model.p4>


#define CPU_CLONE_SESSION_ID 99

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct metadata {
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
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

    // *** ACL
    //
    // Provides ways to override a previous forwarding decision, for example
    // requiring that a packet is cloned/sent to the CPU, or dropped.
    //
    // We use this table to clone all NDP packets to the control plane, so to
    // enable host discovery. When the location of a new host is discovered, the
    // controller is expected to update the L2 and L3 tables with the
    // correspionding brinding and routing entries.

    action send_to_cpu() {
        standard_metadata.egress_port = 9w255;
    }

    action clone3_to_cpu() {
        // Cloning is achieved by using a v1model-specific primitive. Here we
        // set the type of clone operation (ingress-to-egress pipeline), the
        // clone session ID (the CPU one), and the metadata fields we want to
        // preserve for the cloned packet replica.
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, standard_metadata);
    }

    action clone_to_cpu(){
        clone2(CloneType.I2E, CPU_CLONE_SESSION_ID);
    }

    @name(".forward") action forward(bit<9> port) {
        standard_metadata.egress_port = port;
    }
    @name(".bcast") action bcast() {
        standard_metadata.egress_port = 9w100;
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
    table acl_table {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            send_to_cpu;
            clone_to_cpu;
            clone3_to_cpu;
            _nop;
        }
    }
    apply {
        acl_table.apply();
        smac.apply();
        dmac.apply();
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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

