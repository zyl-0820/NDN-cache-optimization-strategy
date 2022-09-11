/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// const bit<16> TYPE_MF = 0x27C0;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

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

struct headers{
    ethernet_t ethernet;
    mf_guid_t mf;
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

    @name(".start") state start {
        transition parse_ethernet;
    }

    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { 
            0x27C0: parse_mf;
            default: accept;
        }
    }

    @name(".parse_mf") state parse_mf{
        packet.extract(hdr.mf);
		transition accept;
    }
}



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action dest_guid_forward(bit<48> nxtHopMac, bit<9> port) {
		hdr.ethernet.dstAddr = nxtHopMac;
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

	
    table dest_guid_exact {
        actions = {
            dest_guid_forward;
            drop;
        }
        key = {
            hdr.mf.dest_guid: exact;
        }
        size = 1024;
    }
	
		
    apply {
            if(hdr.mf.isValid()) {
                if (hdr.mf.mf_type == 1 || hdr.mf.mf_type == 0 || hdr.mf.mf_type == 2) {
                dest_guid_exact.apply();
            }else{
                drop();
            }
            }else{
                drop();
            }
            
		}
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}



/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {

        apply{
            packet.emit(hdr.ethernet);
			packet.emit(hdr.mf);
        }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {   }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {   }
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
