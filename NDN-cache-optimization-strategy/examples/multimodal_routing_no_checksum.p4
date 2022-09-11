/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3>  typeID;
    bit<1>  cfi;
    bit<6>  inPort;
    bit<6>  outPort;
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
    bit<32>   srcAddr;
    bit<32>   dstAddr;
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

header ipv6_t {
    bit<4>      version;
    bit<8>      traffic_class;
    bit<20>     flow_label;
    bit<16>     payload_length;
    bit<8>      nextHdr;
    bit<8>      hopLimit;
    bit<128>    srcAddr;
    bit<128>    dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    vlan_t       vlan;
    ipv4_t       ipv4;
    geo_t        geo;
    ipv6_t       ipv6;
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
            16w0x8100 : parse_vlan;
            16w0x0800 : parse_ipv4;
            16w0x080a : parse_geo;
            16w0x86dd : parse_ipv6;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            16w0x0800 : parse_ipv4;
            16w0x080a : parse_geo;
            16w0x86dd : parse_ipv6;
            default: accept;            
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_geo {
        packet.extract(hdr.geo);
        transition accept;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
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
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    
    action l3_forward(bit<48> dstAddr, bit<6> port) {
        standard_metadata.egress_spec = 9w2;
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.vlan.outPort = port;
    }

    action ipv4_forward(bit<48> dstAddr, bit<6> port) {
        l3_forward(dstAddr, port);
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action geo_forward(bit<48> dstAddr, bit<6> port) {
        l3_forward(dstAddr, port);
        hdr.geo.ttl = hdr.geo.ttl - 1;
    }

    action ipv6_forward(bit<48> dstAddr, bit<6> port) {
        l3_forward(dstAddr, port);
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            _drop;
            NoAction;
        }
        # size = 1024;
        default_action = _drop();
        const entries = {
            # 171.122.183.45
            0xAB7AB700 &&& 0xFFFFFF00 : ipv4_forward(0x080000000111, 1);
            # 172.122.199.61
            0xAC7AC700 &&& 0xFFFFFF00 : ipv4_forward(0x080000000222, 2);
        }
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
        const entries = {
            # 171.122.183.45
            0xAB0AB020 &&& 0xFF0FF0F0 : geo_forward(0x080000000111, 1);
            # 172.122.199.61
            0xAC0AC030 &&& 0xFF0FF0F0 : geo_forward(0x080000000222, 2);
        }
    }

    table ipv6_exact {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            ipv6_forward;
            _drop;
            NoAction;
        }
        # size = 1024;
        default_action = _drop();
        const entries = {
            # 2001:1::1
            0x20010001000000000000000000000001 : ipv6_forward(0x080000000111,1);
            # 2001:1::2
            0x20010001000000000000000000000002 : ipv6_forward(0x080000000222,2);
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        if (hdr.geo.isValid()) {
            geo_ternary.apply();
        }

        if (hdr.ipv6.isValid()) {
            ipv6_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputerChecksum(inout headers  hdr, inout metadata meta) 
{
apply{}
}
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.geo);
        packet.emit(hdr.ipv6);
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
MyComputerChecksum(),
MyDeparser()
) main;
