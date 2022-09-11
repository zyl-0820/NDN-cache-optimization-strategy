#include <core.p4>
#include <v1model.p4>

header fixedTLV_t_1 {
    bit<8> tlv_code;
    bit<8> tlv_length;
}

struct components_metadata_t {
    bit<16> c1;
    bit<16> c2;
    bit<16> c3;
    bit<16> c4;
}

struct flow_metadata_t {
    bit<16> isInPIT;
    bit<8>  hasFIBentry;
    bit<8>  packetType;
    bit<16> isInCS;
}

struct name_metadata_t {
    bit<16> name_hash;
    bit<8>  namesize;
    bit<16> namemask;
    bit<8>  tmp;
    bit<8>  components;
}
struct section_metadata_t {
    bit<8>  Count;
    bit<8>  Index;
}
struct ingress_metadata_t {
    bit<8> tmp;
}

header bigTL_t_0 {
    bit<8>  tl_code;
    bit<8>  tl_len_code;
    bit<32> tl_length;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header hugeTL_t_0 {
    bit<8>  tl_code;
    bit<8>  tl_len_code;
    bit<64> tl_length;
}

header fixedTLV_t {
    bit<8>       tlv_code;
    bit<8>       tlv_length;
    varbit<2024> tlv_value;
}

header mediumTL_t_0 {
    bit<8>  tl_code;
    bit<8>  tl_len_code;
    bit<16> tl_length;
}

header dumbHeaderMedium_NdnlpData_0 {
    bit<8>  tl_code;
    bit<8>  tl_len_code;
    bit<16> tl_length;
}

header dumbHeaderMedium_NdnlpPayload_0 {
    bit<8>  tl_code;
    bit<8>  tl_len_code;
    bit<16> tl_length;
}

header dumbHeader_NdnlpFragCount_0 {
    bit<8> tl_code;
    bit<8> tlv_length;
    bit<8> tl_value;
}

header dumbHeader_NdnlpFragIndex_0 {
    bit<8> tl_code;
    bit<8> tlv_length;
    bit<8> tl_value;
}

header dumbHeader_NdnlpSequence_0 {
    bit<8>  tl_code;
    bit<8>  tlv_length;
    bit<64> tl_value;
}

header smallTL_t {
    bit<8> tl_code;
    bit<8> tl_length;
}

header dumbHeaderSmall_NdnlpData_0 {
    bit<8> tl_code;
    bit<8> tlv_length;
}

header dumbHeaderSmall_NdnlpPayload_0 {
    bit<8> tl_code;
    bit<8> tlv_length;
}

struct metadata {
    components_metadata_t comp_metadata; 
    flow_metadata_t       flow_metadata;
    name_metadata_t       name_metadata;
    ingress_metadata_t    pit_metadata;
    section_metadata_t    section_metadata;
}

struct headers {
    bigTL_t_0                       big_name; 
    bigTL_t_0                       big_tlv0;
    ethernet_t                      ethernet; 
    hugeTL_t_0                      huge_name;
    hugeTL_t_0                      huge_tlv0; 
    mediumTL_t_0                    medium_name; 
    dumbHeaderMedium_NdnlpData_0    medium_ndnlpdata; 
    dumbHeaderMedium_NdnlpPayload_0 medium_ndnlppayload;
    mediumTL_t_0                    medium_tlv0; 
    dumbHeader_NdnlpFragCount_0     ndnlpfragcount;
    dumbHeader_NdnlpFragIndex_0     ndnlpfragindex;
    dumbHeader_NdnlpSequence_0      ndnlpsequence; 
    smallTL_t                       small_name;
    dumbHeaderSmall_NdnlpData_0     small_ndnlpdata; 
    dumbHeaderSmall_NdnlpPayload_0  small_ndnlppayload;
    smallTL_t                       small_tlv0; 
    fixedTLV_t[5]                   components;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    fixedTLV_t_1 tmp_hdr;
    fixedTLV_t_1 tmp_hdr_0;
    fixedTLV_t_1 tmp_hdr_1;
    fixedTLV_t_1 tmp_hdr_2;
    fixedTLV_t_1 tmp_hdr_3;
    fixedTLV_t_1 tmp_hdr_4;
    fixedTLV_t_1 tmp_hdr_5;
    
    state parse_big_name {
        packet.extract(hdr.big_name);
        transition parse_name;
    }
    state parse_big_tlv0 {
        packet.extract(hdr.big_tlv0);
        transition parse_tlv0;
    }
    state parse_components {
        meta.name_metadata.tmp = (packet.lookahead<bit<16>>())[7:0];
        tmp_hdr = packet.lookahead<fixedTLV_t_1>();
        packet.extract(hdr.components.next, (bit<32>)(((bit<32>)tmp_hdr.tlv_length + 32w2) * 8 - 16));
        meta.name_metadata.namesize = meta.name_metadata.namesize - meta.name_metadata.tmp - 8w2;
        transition select(meta.name_metadata.namesize) {
            8w0: parse_default;
            default: parse_components;
        }
    }
    
    state parse_default {
        transition accept;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType, (packet.lookahead<bit<8>>())[7:0]) {
            (16w0x8624 &&& 16w0xffff, 8w0x50 &&& 8w0xff): parse_ndn_lp;
            (16w0x8624 &&& 16w0xffff, 8w0x50 &&& 8w0x0): parse_ndn;
        }
    }
    state parse_huge_name {
        packet.extract(hdr.huge_name);
        transition parse_name;
    }
    state parse_huge_tlv0 {
        packet.extract(hdr.huge_tlv0);
        transition parse_tlv0;
    }
   
    state parse_medium_name {
        packet.extract(hdr.medium_name);
        transition parse_name;
    }
    state parse_medium_ndnlp {
        packet.extract(hdr.medium_ndnlpdata);
        transition parse_ndnlp_sequence;
    }
    state parse_medium_ndnlppayload {
        packet.extract(hdr.medium_ndnlppayload);
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x5: parse_ndn;
            8w0x6: parse_ndn;
            default: parse_default;
        }
    }
    state parse_medium_tlv0 {
        packet.extract(hdr.medium_tlv0);
        meta.flow_metadata.packetType = hdr.medium_tlv0.tl_code;
        transition parse_tlv0;
    }
    
    state parse_name {
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x8: parse_components;
            default: parse_default;
        }
    }
    state parse_ndn {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_tlv0;
            8w0xfe: parse_big_tlv0;
            8w0xff: parse_huge_tlv0;
            default: parse_small_tlv0;
        }
    }
    state parse_ndn_lp {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_ndnlp;
            default: parse_small_ndnlp;
        }
    }
    state parse_ndnlp_fragcount {
        packet.extract(hdr.ndnlpfragcount);
        meta.section_metadata.Count = hdr.ndnlpfragcount.tl_value;
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_ndnlppayload;
            default: parse_small_ndnlppayload;
        }
    }
    state parse_ndnlp_fragindex {
        packet.extract(hdr.ndnlpfragindex);
        meta.section_metadata.Index = hdr.ndnlpfragindex.tl_value;
        transition parse_ndnlp_fragcount;
    }
    state parse_ndnlp_payload {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_ndnlppayload;
            default: parse_small_ndnlppayload;
        }
    }
    state parse_ndnlp_sequence {
        packet.extract(hdr.ndnlpsequence);
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x52: parse_ndnlp_fragindex;
            8w0x54: parse_ndnlp_payload;
        }
    }
    state parse_small_name {
        meta.name_metadata.namesize = (packet.lookahead<bit<16>>())[7:0];
        packet.extract(hdr.small_name);
        transition parse_name;
    }
    state parse_small_ndnlp {
        packet.extract(hdr.small_ndnlpdata);
        transition parse_ndnlp_sequence;
    }
    state parse_small_ndnlppayload {
        packet.extract(hdr.small_ndnlppayload);
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x5: parse_ndn;
            8w0x6: parse_ndn;
            default: parse_default;
        }
    }
    state parse_small_tlv0 {
        packet.extract(hdr.small_tlv0);
        meta.flow_metadata.packetType = hdr.small_tlv0.tl_code;
        transition parse_tlv0;
    }
    state parse_tlv0 {
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x7: size_name;
            default: parse_default;
        }
    }
    state size_name {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_name;
            8w0xfe: parse_big_name;
            8w0xff: parse_huge_name;
            default: parse_small_name;
        }
    }
    state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

register<bit<16>>(32w65536) pit_r;
register<bit<16>>(32w512) section_r;
register<bit<16>>(32w512) section_hash_r;
register<bit<16>>(32w65536) cs_r;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action storeNumOfComponents(bit<8> total) {
        meta.name_metadata.components = total;
    }
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action set_egr(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
        meta.flow_metadata.hasFIBentry = 8w1;
    }
    action set_interestegr() {
        standard_metadata.egress_spec = 9w0;
    }
    action computeNameHashes() {
        hash(meta.comp_metadata.c1, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].tlv_value }, (bit<32>)65536);
        hash(meta.comp_metadata.c2, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].tlv_value, hdr.components[1].tlv_value }, (bit<32>)65536);
        hash(meta.comp_metadata.c3, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].tlv_value, hdr.components[1].tlv_value, hdr.components[2].tlv_value }, (bit<32>)65536);
        hash(meta.comp_metadata.c4, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].tlv_value, hdr.components[1].tlv_value, hdr.components[2].tlv_value, hdr.components[3].tlv_value }, (bit<32>)65536);
    } 
    action computeStoreTablesIndex() {
        hash(meta.name_metadata.name_hash, HashAlgorithm.crc16, (bit<16>)0, { hdr.components[0].tlv_value, hdr.components[1].tlv_value, hdr.components[2].tlv_value, hdr.components[3].tlv_value, hdr.components[4].tlv_value }, (bit<32>)65536);
        computeNameHashes();
    }
    action readPit() {
        pit_r.read(meta.flow_metadata.isInPIT, (bit<32>)meta.name_metadata.name_hash);
    }
    action readPitEntry() {
        readPit();
    }
    action cleanPitEntry() {
        readPit();
        pit_r.write((bit<32>)meta.name_metadata.name_hash, (bit<16>)0x0);
    }
    action readSection() {
        section_r.read(standard_metadata.mcast_grp, (bit<32>)standard_metadata.ingress_port);
    }
    action writesection() {
        section_r.write((bit<32>)standard_metadata.ingress_port,(bit<16>)standard_metadata.mcast_grp);
    }
    action readsection_hash() {
        section_hash_r.read(meta.name_metadata.name_hash, (bit<32>)standard_metadata.ingress_port);
    }
    action writesection_hash() {
        section_hash_r.write((bit<32>)standard_metadata.ingress_port,(bit<16>)meta.name_metadata.name_hash);
    }

    //action setOutputIface(bit<9> out_iface) {
        //standard_metadata.egress_spec = out_iface;
    //}
    action readCs() {
        cs_r.read(meta.flow_metadata.isInCS, (bit<32>)meta.name_metadata.name_hash);
    }
    action readCsEntry() {
        readCs();
    }
    action addCstoMutist() {
        meta.flow_metadata.isInPIT = meta.flow_metadata.isInPIT | 16w1;
    }
    action updateonlyCs() {
        cs_r.write((bit<32>)meta.name_metadata.name_hash, 16w1);
    }
    action updateCsEntry() {
        meta.flow_metadata.isInPIT = meta.flow_metadata.isInPIT | 16w1;
        cs_r.write((bit<32>)meta.name_metadata.name_hash, 16w1);
    }
    action multicast() {
        standard_metadata.mcast_grp = meta.flow_metadata.isInPIT;
    }
    action updatePit_entry() {
        meta.pit_metadata.tmp = (bit<8>)(meta.flow_metadata.isInPIT & (bit<16>)(9w1 << (bit<8>)standard_metadata.ingress_port));
        meta.flow_metadata.isInPIT = meta.flow_metadata.isInPIT | (bit<16>)(9w1 << (bit<8>)standard_metadata.ingress_port);
        pit_r.write((bit<32>)meta.name_metadata.name_hash, (bit<16>)meta.flow_metadata.isInPIT);
    }
    table section_table {
        actions = {
            readSection;
            _drop;
        }
        key = {
            hdr.ndnlpfragcount.isValid(): exact;
        }
        size = 2;
    }
    table updatesection_table {
        actions = {
            writesection;
        }
        size = 1;
    }
    table sectionhashread_table {
        actions = {
            readsection_hash;
        }
        size = 1;
    }
    table sectionhashwrite_table {
        actions = {
            writesection_hash;
        }
        size = 1;
    }


    table count_table {
        actions = {
            storeNumOfComponents;
            _drop;
        }
        key = {
            hdr.components[0].isValid(): exact;
            hdr.components[1].isValid(): exact;
            hdr.components[2].isValid(): exact;
            hdr.components[3].isValid(): exact;
            hdr.components[4].isValid(): exact;
        }
        size = 5;
    }
    table fib_table {
        actions = {
            set_egr;
            _drop;
        }
        key = {
            meta.name_metadata.components: exact;
            meta.comp_metadata.c1        : ternary;
            meta.comp_metadata.c2        : ternary;
            meta.comp_metadata.c3        : ternary;
            meta.comp_metadata.c4        : ternary;
            meta.name_metadata.name_hash : ternary;
        }
    }
    table interestcs_table {
        actions = {
            set_interestegr;
        }
        size = 1;
    }
    table hashName_table {
        actions = {
            computeStoreTablesIndex;
        }
        size = 1;
    }
    table pit_table {
        actions = {
            readPitEntry;
            cleanPitEntry;
        }
        key = {
            meta.flow_metadata.packetType: exact;
        }
        size = 2;
    }
     table cs_table {
        actions = {
            readCsEntry;
        }
        size = 1;
    }
    table updatecs_table {
        actions = {
            addCstoMutist;
            updateCsEntry;
        }
        key = {
            hdr.ndnlpfragcount.isValid(): exact;
        }
        size = 2;
    }
    table updateonlycs_table {
        actions = {
            updateonlyCs;
        }
        size = 1;
    }
    table routeData_table {
        actions = {
            multicast;
        }
        size = 1;
    }
    table updatePit_table {
        actions = {
            updatePit_entry;
            _drop;
        }
        key = {
            meta.flow_metadata.hasFIBentry: exact;
        }
        size = 2;
    }
    table updatehitcsPit_table {
        actions = {
            updatePit_entry;
        }
        size = 1;
    }
    apply {
        if(!hdr.components[0].isValid()) {
            section_table.apply();
            if(meta.section_metadata.Count == (meta.section_metadata.Index + 1)){
                sectionhashread_table.apply();
                updateonlycs_table.apply();
            }
        }
        else {
            count_table.apply();
            hashName_table.apply();
            pit_table.apply();
            if (meta.flow_metadata.packetType == 8w0x5) {
                cs_table.apply();
                if(meta.flow_metadata.isInCS == 16w0){
                    if (meta.flow_metadata.isInPIT == 16w0) {
                        fib_table.apply();
                    }
                    updatePit_table.apply();
                }
                else {
                     interestcs_table.apply();
                     updatehitcsPit_table.apply();
                }
            }
            else {
                updatecs_table.apply();
                routeData_table.apply();
                if(hdr.ndnlpfragcount.isValid()) {
                    updatesection_table.apply();
                    sectionhashwrite_table.apply();
                }
            }
       }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.small_ndnlpdata);
        packet.emit(hdr.medium_ndnlpdata);
        packet.emit(hdr.ndnlpsequence);
        packet.emit(hdr.ndnlpfragindex);
        packet.emit(hdr.ndnlpfragcount);
        packet.emit(hdr.small_ndnlppayload);
        packet.emit(hdr.medium_ndnlppayload);
        packet.emit(hdr.small_tlv0);
        packet.emit(hdr.huge_tlv0);
        packet.emit(hdr.big_tlv0);
        packet.emit(hdr.medium_tlv0);
        packet.emit(hdr.small_name);
        packet.emit(hdr.huge_name);
        packet.emit(hdr.big_name);
        packet.emit(hdr.medium_name);
        packet.emit(hdr.components);
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

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

