#include <core.p4>
#include <v1model_encrypt.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<8>  versionIhl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<16> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header geo_t {
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
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

struct headers {
    @name(".ethernet")
    ethernet_t ethernet;
    @name(".ipv4")
    ipv4_t     ipv4;
    geo_t      geo;
}

/*
 * All metadata, globally used in the program, also  needs to be assembed
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */

struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    @name(".start") state start {
        transition parse_ethernet;
    }

    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x0800 : parse_ipv4;
            16w0x080a : parse_geo;
            default: accept;
        }
    }

    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    @name(".parse_geo") state parse_geo {
        packet.extract(hdr.geo);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    action l3_forward(bit<48> dstAddr, bit<9> port) {
        // standard_metadata.egress_spec = 9w1;
        standard_metadata.egress_port = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        l3_forward(dstAddr, port);
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action geo_forward(bit<48> dstAddr, bit<9> port) {
        l3_forward(dstAddr, port);
        hdr.geo.ttl = hdr.geo.ttl - 1;
    }

    action send_to_cpu() {
       standard_metadata.egress_spec = 9w255;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
             ipv4_forward;
             _drop;
            //  NoAction;
            //  send_to_cpu;
        }
        # size = 1024;
        default_action = _drop;
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
        # size = 1024;
        default_action = _drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        if (hdr.geo.isValid()) {
            geo_ternary.apply();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyEncryptWithPayload(inout headers hdr, inout metadata meta) {
    apply {
        if (hdr.geo.isValid()) {
            encrypt_with_payload();
            // decrypt_with_payload();
        }
        
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyEncryptWithPayload(),
MyComputeChecksum(),
MyDeparser()
) main;
