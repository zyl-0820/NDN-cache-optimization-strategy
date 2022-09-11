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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    geo_t        geo;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
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

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
extern void decrypt_with_payload();
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
	
	action l3_forward(bit<48> dstAddr, bit<9> port) {
        // standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
        //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        // hdr.vlan.outPort = port;
    }
	
    action ipv4_de_encry () {
        //本acntion添加对数据包的解密操作和recirulate动作，包括以下三个部分；
        //（1）对于IPsec的解密操作，IPSec中的IP包头要被去掉，并同步在pd headers中去除包头；
        // (2) 将ethertype字段根据原IPSec包头中的协议号更改；
        // (3) recirculate,将数据发送至parser重新操作；
        decrypt_with_payload();
        standard_metadata.recirculate_flag = 1;
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

    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
             ipv4_forward;
             #_drop;
             NoAction;
             send_to_cpu;
        }
        # size = 1024;
    }

     table ipv4_spd {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            ipv4_de_encry;
            NoAction;
        }
        default_action= NoAction;
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
            if(hdr.ipv4.protocol==8w50) {
                if(ipv4_spd.apply().miss){
                    _drop();
                }
            }else {
                if(ipv4_exact.apply().miss){
                    _drop();
                }
            }
        }
        else if (hdr.geo.isValid()) {
            if(geo_ternary.apply().miss){
                    _drop();
                }
        }
        else{
             _drop();
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
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        /**update_checksum(
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
           HashAlgorithm.csum16);**/
            //decrypt_with_payload();
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.geo);

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
MyComputeChecksum(),
MyDeparser()
) main;

