/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <core.p4>
#include <v1model.p4>


// typedef bit<16>  mcast_group_id_t;

//------------------------------------------------------------------------------
// HEADER DEFINITIONS
//------------------------------------------------------------------------------

header ethernet_t {
    bit<48>  dst_addr;
    bit<48>  src_addr;
    bit<16>  etherType;
}

header powerlink_t {
    bit<1>    saved;
    bit<7>    message_type;
    bit<8>    dst_node;
    bit<8>    src_node;
}

struct headers {
    ethernet_t ethernet;
	powerlink_t powerlink;
}

struct local_metadata_t {
    bool        is_multicast;
}


//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

parser ParserImpl (packet_in packet,
                   out headers hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    @name(".start") state start {
        transition parse_ethernet;
    }

	@name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x88ab: parse_epl;
            default: accept;
        }
    }

    @name(".parse_epl") state parse_epl {
        packet.extract(hdr.powerlink);
        transition accept;
    }
}


control VerifyChecksumImpl(inout headers hdr,
                           inout local_metadata_t meta)
{
    apply { /* EMPTY */ }
}


control MyIngress (inout headers    hdr,
                         inout local_metadata_t    local_metadata,
                         inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egress_port(bit<9> port_num) {
        standard_metadata.egress_port = port_num;
    }

    // action set_multicast_group(mcast_group_id_t gid) {
    //     standard_metadata.mcast_grp = gid;
    //     local_metadata.is_multicast = true;
    // }

    table l3_exact_table {
        key = {
            hdr.powerlink.dst_node: exact;
        }
        actions = {
            set_egress_port;
            // set_multicast_group;
            @defaultonly drop;
        }
        const default_action = drop;
        @name("l3_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }


    apply {
        if (hdr.powerlink.isValid()){
            l3_exact_table.apply();
        }else{
            drop();
        }
            
        }
}


control EgressPipeImpl (inout headers hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {
        if (local_metadata.is_multicast == true &&
              standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}


control ComputeChecksumImpl(inout headers hdr,
                            inout local_metadata_t local_metadata)
{
    apply { /* EMPTY */ }
}


control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
		packet.emit(hdr.powerlink);
    }
}


V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    MyIngress(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
