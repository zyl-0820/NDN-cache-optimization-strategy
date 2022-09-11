/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9> port_t;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MF = 0x27C0; 
const bit<9> PORT_ONOS =255;
const port_t CPU_PORT = 255;

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
header mf_t{
    bit<32> mf_type;
}

header Segmentdata_t{
    bit<32> mf_type;
    bit<32> src_guid;
    bit<32> dest_guid;
    bit<32> src_na;
    bit<32> dest_na;
    bit<32> pld_size;
    bit<32> seq_num;
}


header CSYN_t{
    bit<32> mf_type;
    bit<32> src_guid;
    bit<32> dest_guid;
    bit<32> src_na;
    bit<32> dest_na;
    bit<32> chk_pkt_count;
}
header CSYN_ACK_t{
    bit<32> mf_type;
    bit<32> src_guid;
    bit<32> dest_guid;
    bit<32> src_na;
    bit<32> dest_na;
    bit<32> chk_pkt_count;
}
header assoc_t{
    bit<32> mf_type;
    bit<32> client_guid;
    bit<32> host_guid;
    bit<16> weight;
}
header deassoc_t{
    bit<32> mf_type;
    bit<32> entity_guid;
    bit<32> host_guid;
}

// Packet-in header. Prepended to packets sent to the controller and used to
// carry the original ingress port where the packet was received.
@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

struct headers{
    ethernet_t ethernet;
    ipv4_t ipv4;
    mf_t mf;
    Segmentdata_t Segmentdata;
    CSYN_t CSYN;
    CSYN_ACK_t CSYN_ACK;
    assoc_t assoc;
    deassoc_t deassoc;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
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
        transition select(standard_metadata.ingress_port) {
            255: parse_packet_out;
            default: parse_ethernet;
        }    
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { 
            0x800: parse_ipv4;
            0x27C0: parse_mf;
            default: accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;
    }


    state parse_mf{
        packet.extract(hdr.mf);
        transition select(hdr.mf.mf_type) { 
            0: parse_Segmentdata; 
            1: parse_CSYN;       
            2: parse_CSYN_ACK; 
            6: parse_assoc;  
            7: parse_deassoc;  
            default: accept;
        }
    }

    state parse_Segmentdata{
        packet.extract(hdr.Segmentdata);
        transition accept;
    }

    state parse_CSYN{
        packet.extract(hdr.CSYN);
        transition accept;
    }

    state parse_CSYN_ACK{
        packet.extract(hdr.CSYN_ACK);
        transition accept;
    }

    state parse_assoc{
        packet.extract(hdr.assoc);
        transition accept;
    }

    state parse_deassoc{
        packet.extract(hdr.deassoc);
        transition accept;
    }
}




/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action set_out_port(bit<9> port) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        standard_metadata.egress_spec = port;
    }

    action controller_forward() {
        standard_metadata.egress_spec = 255;
    }

    action dest_guid_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action dest_na_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }


    /*table t_l2_fwd {
        actions = {
            set_out_port;
            send_to_cpu;
            drop;
        }
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.dstAddr           : ternary;
            hdr.ethernet.srcAddr           : ternary;
            hdr.ethernet.etherType         : ternary;
        }
        default_action = send_to_cpu();
    }

    table assoc_deassoc_exact {
        actions = {
            controller_forward;
            drop;
        }
        key = {

        }
        size = 1024;
        default_action = controller_forward();   //default to onos
    }*/

    table Segmentdata_dest_guid_exact {
        actions = {
            dest_guid_forward;
            drop;
        }
        key = {
            hdr.Segmentdata.dest_guid: exact;
        }
        size = 1024;
        default_action = drop();
    }
    table CSYN_dest_guid_exact {
        actions = {
            dest_guid_forward;
            drop;
        }
        key = {
            hdr.CSYN.dest_guid: exact;
        }
        size = 1024;
        default_action = drop();
    }
    table CSYN_ACK_dest_guid_exact {
        actions = {
            dest_guid_forward;
            drop;
        }
        key = {
            hdr.CSYN_ACK.dest_guid: exact;
        }
        size = 1024;
        default_action = drop();
    }

    table Segmentdata_dest_na_exact {
        actions = {
            dest_na_forward;
            drop;
        }
        key = {
            hdr.Segmentdata.dest_na: exact;
        }
        size = 1024;
        default_action = drop();
    }    
    table CSYN_dest_na_exact {
        actions = {
            dest_na_forward;
            drop;
        }
        key = {
            hdr.CSYN.dest_na: exact;
        }
        size = 1024;
        default_action = drop();
    }
    table CSYN_ACK_dest_na_exact {
        actions = {
            dest_na_forward;
            drop;
        }
        key = {
            hdr.CSYN_ACK.dest_na: exact;
        }
        size = 1024;
        default_action = drop();
    }

    
    apply {

	if (standard_metadata.ingress_port == CPU_PORT) {
            // Packet received from CPU_PORT, this is a packet-out sent by the
            // controller. Skip table processing, set the egress port as
            // requested by the controller (packet_out header) and remove the
            // packet_out header.
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        }else{
		/*if (t_l2_fwd.apply().hit) {
        	    return;
        	}*/
		if (hdr.assoc.isValid() || hdr.deassoc.isValid()) {
        	    controller_forward();
        	}
	        else if(Segmentdata_dest_guid_exact.apply().miss){
	            Segmentdata_dest_na_exact.apply();
	        }
        	else if(CSYN_dest_guid_exact.apply().miss){
        	    CSYN_dest_na_exact.apply();
        	}
        	else if(CSYN_ACK_dest_guid_exact.apply().miss){
        	    CSYN_ACK_dest_na_exact.apply();
        	}

	}

    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}



/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {

        apply{
            //packet.emit(hdr);
            packet.emit(hdr.packet_in);
            packet.emit(hdr.ethernet);
            packet.emit(hdr.ipv4);
            packet.emit(hdr.Segmentdata);
            packet.emit(hdr.CSYN);
            packet.emit(hdr.CSYN_ACK);
            packet.emit(hdr.assoc);
            packet.emit(hdr.deassoc);
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
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
verifyChecksum(),
MyIngress(),
egress(),
computeChecksum(),
MyDeparser()
) main;
