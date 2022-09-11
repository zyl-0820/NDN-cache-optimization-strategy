#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

@controller_header("packet_in") header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _pad;
}

@controller_header("packet_out") header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _pad;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header mf_guid_t{
    bit<32> mf_type;
    bit<32> src_guid;
    bit<32> dest_guid;
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

struct headers {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    mf_guid_t           mf;
}

struct metadata {
    bit<14> ecmp_select;
}

parser MyParser(packet_in pkt, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition select(standard_metadata.ingress_port) {
            255: parse_packet_out;
            default: parse_ethernet;
        }
    }
    state parse_packet_out {
        pkt.extract(hdr.packet_out);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            0x27c0: parse_mf;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

    state parse_mf {
        pkt.extract(hdr.mf);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

extern void encrypt_with_payload(in bit<32> spi, in bit<32> srcip, in bit<32> dstip, in bit<32> hdrlen);
extern void decrypt_with_payload();
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action dest_guid_forward(bit<48> nxtHopMac, bit<9> port) {
        hdr.ethernet.dstAddr = nxtHopMac;
        standard_metadata.egress_spec = port;
    }

    action ipv4_ipsec(bit<32> spi, bit<32> sAdrress, bit<32> dAddress) {
        //此处添加加密操作，需要注意的是，hdr中原来的IP包头需要被新加入的IP包头信息所取代，
        //此处需要我们再操作，同时根据加密过程中指针的移动来操作；
        //另，ethertype字段确定为0800;
        hdr.ethernet.etherType=0x800;
        encrypt_with_payload(spi,sAdrress,dAddress,32w20);
    }

    action mf_ipsec(bit<32> spi, bit<32> sAdrress, bit<32> dAddress) {

        //此处添加加密操作，需要注意的是，hdr中原来的mf包头需要被新加入的IP包头信息所取代，
        //此处需要我们再操作，同时根据加密过程中指针的移动来操作；另，ethertype字段改为0800；要进一步细化并给出方案；
        encrypt_with_payload(spi,sAdrress,dAddress,32w12);
    }

    action ipv4_de_encry () {
        //本acntion添加对数据包的解密操作和recirulate动作，包括以下三个部分；
        //（1）对于IPsec的解密操作，IPSec中的IP包头要被去掉，并同步在pd headers中去除包头；
        // (2) 将ethertype字段根据原IPSec包头中的协议号更改；
        // (3) recirculate,将数据发送至parser重新操作；
        decrypt_with_payload();
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
        default_action = _drop();
    }

    table dest_guid_exact {
        actions = {
            dest_guid_forward;
            _drop;
        }
        key = {
            hdr.mf.dest_guid: exact;
        }
        size = 1024;
    }

    table ipv4_spi {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            ipv4_ipsec;
            NoAction;
        }
        default_action= NoAction;
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

    table dest_guid_spi {
        key= {
            hdr.mf.dest_guid: exact;
        }
        actions = {
            mf_ipsec;
            NoAction;
        }
        default_action= NoAction;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if(hdr.ipv4.protocol==8w50) {
                ipv4_spd.apply();
            }else {
                ipv4_lpm.apply();
                ipv4_spi.apply();
            }
        }else if (hdr.mf.isValid()) {
            if(hdr.mf.mf_type==0||hdr.mf.mf_type==1||hdr.mf.mf_type==2) {
                dest_guid_exact.apply();
                dest_guid_spi.apply();
            }else {
                _drop();
            }
        }else {
            _drop();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        //update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

