#include <core.p4>
#include <psa.p4>

// In: 000000000000000000000000
// Out: 11110000

struct data {
    bit<1> first;
    bit<1> second;
    bit<1> third;
}

header empty_t { }

header dummy_t {
    bit<1> f1;
    data f2;
    bit<4> padding;
}

struct empty_metadata_t {
}

struct metadata {
}

struct headers {
    empty_t empty;
    dummy_t[4] dummy;
}
parser IngressParserImpl(packet_in packet,
                         out headers hdr,
                         inout metadata meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_metadata_t resubmit_meta,
                         in empty_metadata_t recirculate_meta) {
    state parse_ethernet {
        packet.extract(hdr.empty);
        packet.extract(hdr.dummy.next);
        packet.extract(hdr.dummy.next);
        packet.extract(hdr.dummy.next);
        packet.extract(hdr.dummy.next);
        transition accept;
    }
    state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply {
       data d = {~hdr.dummy[1].f2.second, ~hdr.dummy[1].f2.second, ~hdr.dummy[1].f2.second};
       hdr.dummy[1].f1 = (bit<1>)hdr.empty.isValid();
       hdr.dummy[1].f2 = d;
       hdr.dummy[2].setInvalid();
       hdr.dummy.pop_front(1);
    }
}


control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    apply { }
}

parser EgressParserImpl(packet_in buffer,
                        out headers hdr,
                        inout metadata meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_metadata_t normal_meta,
                        in empty_metadata_t clone_i2e_meta,
                        in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

control IngressDeparserImpl(packet_out buffer,
                            out empty_metadata_t clone_i2e_meta,
                            out empty_metadata_t resubmit_meta,
                            out empty_metadata_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    apply {
       buffer.emit(hdr.dummy);
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_metadata_t clone_e2e_meta,
                           out empty_metadata_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    apply {
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
