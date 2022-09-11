/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9> port_t;
typedef bit<48> mac_t;
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

header mf_guid_t{
    bit<32> mf_type;
	bit<32> src_guid;
    bit<32> dest_guid;
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
    mf_guid_t mf;
    geo_t geo;
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

    @name(".start") state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }    
    }

    @name(".parse_packet_out") state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { 
            16w0x080a : parse_geo;
            TYPE_MF: parse_mf;
            default: accept;
        }
    }

    @name(".parse_geo") state parse_geo {
        packet.extract(hdr.geo);
        transition accept;
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

    action send_to_cpu() {
        // standard_metadata.egress_spec = CPU_PORT;
        standard_metadata.egress_port = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action dest_guid_forward(mac_t nxtHopMac, port_t port) {
		hdr.ethernet.dstAddr = nxtHopMac;
        // standard_metadata.egress_spec = port;
        standard_metadata.egress_port = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // table assoc_deassoc_exact {
    //     actions = {
    //         send_to_cpu;
    //         drop;
    //     }

    //     size = 1024;
    //     default_action = send_to_cpu();   //default to onos
    // }
	
    table dest_guid_exact {
        actions = {
            dest_guid_forward;
            send_to_cpu;
        }
        key = {
            hdr.mf.dest_guid: exact;
        }
        size = 1024;
        default_action = send_to_cpu();
    }
	
		
    apply {
	        if (standard_metadata.ingress_port == CPU_PORT) {
				// standard_metadata.egress_spec = hdr.packet_out.egress_port;
                standard_metadata.egress_port = hdr.packet_out.egress_port;
				hdr.packet_out.setInvalid();
			} else {
                if(hdr.geo.isValid()){
                    send_to_cpu();
                }
                else if(hdr.mf.isValid()) {
				if (hdr.mf.mf_type == 6 || hdr.mf.mf_type == 7){
					send_to_cpu();
					// return;
				}
		
				if (hdr.mf.mf_type == 1 || hdr.mf.mf_type == 0 || hdr.mf.mf_type == 2) {
                    if(dest_guid_exact.apply().miss){
                        send_to_cpu();
                    }
					
					// return;
				}}else{
                drop();
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
            packet.emit(hdr.packet_in);
            packet.emit(hdr.ethernet);
             //packet.emit(hdr.packet_in);
			packet.emit(hdr.mf);
            //packet.emit(hdr.geo);
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
