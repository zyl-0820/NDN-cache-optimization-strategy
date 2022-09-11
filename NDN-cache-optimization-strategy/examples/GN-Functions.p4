/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PORT_ONOS 255
#define CPU_CLONE_SESSION_ID 96

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_GEO = 0x8947;
const bit<4> TYPE_geo_beacon = 0x0001;
const bit<4> TYPE_geo_gbc = 0x0004;     
const bit<4> TYPE_geo_tsb = 0x0005; 



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

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



header geo_t{
    bit<4>  version;
    bit<4>  nh_basic;
    bit<8>  reserved_basic;
    bit<8>  lt;
    bit<8>  rhl;
    bit<4> nh_common;
    bit<4> reserved_common_a;
    bit<4> ht;
    bit<4> hst;
    bit<8> tc;
    bit<8> flag;
    bit<16> pl;
    bit<8> mhl;
    bit<8> reserved_common_b;
}

header gbc_t{
    bit<16> sn;
    bit<16> reserved_gbc_a;
    bit<64> gnaddr;
    bit<32> tst;
    bit<32> lat;
    bit<32> longg;
    bit<1> pai;
    bit<15> s;
    bit<16> h;
    bit<32> geoAreaPosLat; //请求区域中心点的维度
    bit<32> geoAreaPosLon; //请求区域中心点的经度
    bit<16> disa;
    bit<16> disb;
    bit<16> angle;
    bit<16> reserved_gbc_b; 
}


header beacon_t{
    bit<64> gnaddr;
    bit<32> tst;
    bit<32> lat;
    bit<32> longg;
    bit<1> pai;
    bit<15> s;
    bit<16> h;
    //是否可以在header中使用结构体
}

@controller_header("packet_in")
header onos_in_header_t {
    bit<9>  ingress_port;
    bit<7>      _pad;
}

@controller_header("packet_out")
header onos_out_header_t {
    bit<9>  egress_port;
    bit<7>      _pad;
}


struct headers{
    onos_out_header_t onos_out;
    onos_in_header_t onos_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    geo_t geo;
    gbc_t gbc;
    beacon_t beacon;
    
}

struct metadata {
    /* empty */
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {


    state start {
        transition select(standard_metadata.ingress_port){
            PORT_ONOS: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.onos_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { 
            TYPE_IPV4: parse_ipv4;
            TYPE_GEO: parse_geo;
            default: accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;
    }


    state parse_geo{
        packet.extract(hdr.geo);
        transition select(hdr.geo.ht) { //要根据ht的大小来判断选取的字段
            TYPE_geo_beacon: parse_beacon; //0x01
            TYPE_geo_gbc: parse_gbc;       //0x04
            TYPE_geo_tsb: parse_tsb;  //0x05  
            default: accept;
        }
    }

    state parse_beacon{
        packet.extract(hdr.beacon);
        transition accept;
    }

    state parse_gbc{
        packet.extract(hdr.gbc);
        transition accept;
    }
    
    /********gangjia de*/
    state parse_tsb{
        //packet.extract(hdr.tsb);
        transition accept;
    }
    
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action unicast(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action fwd2ONOS() {
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, standard_metadata);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }


    action multicast(bit <16> grpid) {
        standard_metadata.mcast_grp = grpid;
    }//用于组播的动作函数

    table gbc_exact {
        actions = {
            multicast;//这是新加的动作
            unicast;
            fwd2ONOS;
        }
        key = {
            hdr.gbc.geoAreaPosLat: exact;
            hdr.gbc.geoAreaPosLon: exact;
            hdr.gbc.disa: exact;
            hdr.gbc.disb: exact;
        }
        size = 1024;
        default_action = fwd2ONOS();
    }

    table beacon_exact {
        actions = {
            multicast;
            unicast;
            fwd2ONOS;
        }
        // key = {
            
        // }
        size = 1024;
    }

    table eth_exact {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dstAddr: ternary;
            hdr.ethernet.srcAddr: ternary;
            hdr.ethernet.etherType: ternary;
        }
        actions = {
            fwd2ONOS;
            drop;
        }
    }


    apply {
        if (hdr.onos_out.isValid()) {
            // Set the egress port to that found in the packet-out metadata...
            standard_metadata.egress_spec = hdr.onos_out.egress_port;
            // Remove the packet-out header...
            hdr.onos_out.setInvalid();
            // Exit the pipeline here, no need to go through other tables.
            exit;
        }
        
        
        if (hdr.gbc.isValid()) {
            gbc_exact.apply();
        }
        else if(hdr.beacon.isValid()){
            beacon_exact.apply();
        }
        
        eth_exact.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (standard_metadata.egress_port == PORT_ONOS) {
            hdr.onos_in.setValid();
            hdr.onos_in.ingress_port = standard_metadata.ingress_port;
            exit;
        }
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            drop();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
        apply{
            packet.emit(hdr);
        }
}



/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
verifyChecksum(),
MyIngress(),
MyEgress(),
computeChecksum(),
MyDeparser()
) main;
