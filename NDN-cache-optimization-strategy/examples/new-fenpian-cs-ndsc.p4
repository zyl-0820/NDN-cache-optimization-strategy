#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

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
    bit<16>                 c1;
    bit<16>                 c2;
    bit<16>                 c3;
    bit<16>                 c4;
    bit<32>                 isInPIT;
    bit<8>                  hasFIBentry;
    bit<8>                  packetType;
    bit<32>                 isInCS;
    bit<16>                 name_hash;
    bit<8>                  namesize;
    bit<16>                 namemask;
    bit<8>                  name_tmp;
    bit<8>                  components;
    bit<8>                  Count;
    bit<8>                  Index;
    bit<8>                  ingress_tmp;
    bit<1>                  hdr_ndnlpfragcount_flag;
    bit<1>                  hdr_component1_flag;
    bit<1>                  hdr_component2_flag;
    bit<1>                  hdr_component3_flag;
    bit<1>                  hdr_component4_flag;
    bit<1>                  hdr_component5_flag;
    //bool                    hdr_flag1;
    //bool                    hdr_flag2;
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
    fixedTLV_t                      component1;
    fixedTLV_t                      component2;
    fixedTLV_t                      component3;
    fixedTLV_t                      component4;
    fixedTLV_t                      component5;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
     //bit<8>          tmp_hdr;
    // fixedTLV_t_1 tmp_hdr;
    // fixedTLV_t_1 tmp_hdr_0;
    // fixedTLV_t_1 tmp_hdr_1;
    // fixedTLV_t_1 tmp_hdr_2;
    // fixedTLV_t_1 tmp_hdr_3;
    // fixedTLV_t_1 tmp_hdr_4;
    // fixedTLV_t_1 tmp_hdr_5;
    @name(".parse_big_name") state parse_big_name {
        packet.extract(hdr.big_name);
        transition parse_name;
    }
    @name(".parse_big_tlv0") state parse_big_tlv0 {
        packet.extract(hdr.big_tlv0);
        transition parse_tlv0;
    }
    @name(".parse_component1") state parse_component1 {
        meta.name_tmp = (packet.lookahead<bit<16>>())[7:0];
        //tmp_hdr = (packet.lookahead<bit<16>>())[15:8];
        packet.extract(hdr.component1, (bit<32>)(((bit<32>)meta.name_tmp + 32w2) * 8 - 16));
        meta.namesize = meta.namesize - meta.name_tmp - 8w2;
        transition select(meta.namesize) {
            8w0: parse_default;
            default: parse_component2;
        }
    }
    @name(".parse_component2") state parse_component2 {
        meta.name_tmp = (packet.lookahead<bit<16>>())[7:0];
        //tmp_hdr = (packet.lookahead<bit<16>>())[15:8];
        packet.extract(hdr.component2, (bit<32>)(((bit<32>)meta.name_tmp + 32w2) * 8 - 16));
        meta.namesize = meta.namesize - meta.name_tmp - 8w2;
        transition select(meta.namesize) {
            8w0: parse_default;
            default: parse_component3;
        }
    }
    @name(".parse_component3") state parse_component3 {
        meta.name_tmp = (packet.lookahead<bit<16>>())[7:0];
        //tmp_hdr = (packet.lookahead<bit<16>>())[15:8];
        packet.extract(hdr.component3, (bit<32>)(((bit<32>)meta.name_tmp + 32w2) * 8 - 16));
        meta.namesize = meta.namesize - meta.name_tmp - 8w2;
        transition select(meta.namesize) {
            8w0: parse_default;
            default: parse_component4;
        }
    }
    @name(".parse_component4") state parse_component4 {
        meta.name_tmp = (packet.lookahead<bit<16>>())[7:0];
        //tmp_hdr = (packet.lookahead<bit<16>>())[15:8];
        packet.extract(hdr.component4, (bit<32>)(((bit<32>)meta.name_tmp + 32w2) * 8 - 16));
        meta.namesize = meta.namesize - meta.name_tmp - 8w2;
        transition select(meta.namesize) {
            8w0: parse_default;
            default: parse_component5;
        }
    }
    @name(".parse_component5") state parse_component5 {
        meta.name_tmp = (packet.lookahead<bit<16>>())[7:0];
        //tmp_hdr = (packet.lookahead<bit<16>>())[15:8];
        packet.extract(hdr.component5, (bit<32>)(((bit<32>)meta.name_tmp + 32w2) * 8 - 16));
        meta.namesize = meta.namesize - meta.name_tmp - 8w2;
        transition select(meta.namesize) {
            default: parse_default;
        }
    }
    @name(".parse_default") state parse_default {
        transition accept;
    }
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType, (packet.lookahead<bit<8>>())[7:0]) {
            (16w0x8624 &&& 16w0xffff, 8w0x50 &&& 8w0xff): parse_ndn_lp;
            (16w0x8624 &&& 16w0xffff, 8w0x50 &&& 8w0x0): parse_ndn;
        }
    }
    @name(".parse_huge_name") state parse_huge_name {
        packet.extract(hdr.huge_name);
        transition parse_name;
    }
    @name(".parse_huge_tlv0") state parse_huge_tlv0 {
        packet.extract(hdr.huge_tlv0);
        transition parse_tlv0;
    }
    @name(".parse_medium_name") state parse_medium_name {
        packet.extract(hdr.medium_name);
        transition parse_name;
    }
    @name(".parse_medium_ndnlp") state parse_medium_ndnlp {
        packet.extract(hdr.medium_ndnlpdata);
        transition parse_ndnlp_sequence;
    }
    @name(".parse_medium_ndnlppayload") state parse_medium_ndnlppayload {
        packet.extract(hdr.medium_ndnlppayload);
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x5: parse_ndn;
            8w0x6: parse_ndn;
            default: parse_default;
        }
    }
    @name(".parse_medium_tlv0") state parse_medium_tlv0 {
        packet.extract(hdr.medium_tlv0);
        meta.packetType = hdr.medium_tlv0.tl_code;
        transition parse_tlv0;
    }
    @name(".parse_name") state parse_name {
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x8: parse_component1;
            default: parse_default;
        }
    }
    @name(".parse_ndn") state parse_ndn {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_tlv0;
            8w0xfe: parse_big_tlv0;
            8w0xff: parse_huge_tlv0;
            default: parse_small_tlv0;
        }
    }
    @name(".parse_ndn_lp") state parse_ndn_lp {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_ndnlp;
            default: parse_small_ndnlp;
        }
    }
    @name(".parse_ndnlp_fragcount") state parse_ndnlp_fragcount {
        packet.extract(hdr.ndnlpfragcount);
        meta.Count = hdr.ndnlpfragcount.tl_value;
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_ndnlppayload;
            default: parse_small_ndnlppayload;
        }
    }
    @name(".parse_ndnlp_fragindex") state parse_ndnlp_fragindex {
        packet.extract(hdr.ndnlpfragindex);
        meta.Index = hdr.ndnlpfragindex.tl_value;
        transition parse_ndnlp_fragcount;
    }
    @name(".parse_ndnlp_payload") state parse_ndnlp_payload {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_ndnlppayload;
            default: parse_small_ndnlppayload;
        }
    }
    @name(".parse_ndnlp_sequence") state parse_ndnlp_sequence {
        packet.extract(hdr.ndnlpsequence);
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x52: parse_ndnlp_fragindex;
            8w0x54: parse_ndnlp_payload;
        }
    }
    @name(".parse_small_name") state parse_small_name {
        meta.namesize = (packet.lookahead<bit<16>>())[7:0];
        packet.extract(hdr.small_name);
        transition parse_name;
    }
    @name(".parse_small_ndnlp") state parse_small_ndnlp {
        packet.extract(hdr.small_ndnlpdata);
        transition parse_ndnlp_sequence;
    }
    @name(".parse_small_ndnlppayload") state parse_small_ndnlppayload {
        packet.extract(hdr.small_ndnlppayload);
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x5: parse_ndn;
            8w0x6: parse_ndn;
            default: parse_default;
        }
    }
    @name(".parse_small_tlv0") state parse_small_tlv0 {
        packet.extract(hdr.small_tlv0);
        meta.packetType = hdr.small_tlv0.tl_code;
        transition parse_tlv0;
    }
    @name(".parse_tlv0") state parse_tlv0 {
        transition select((packet.lookahead<bit<8>>())[7:0]) {
            8w0x7: size_name;
            default: parse_default;
        }
    }
    @name(".size_name") state size_name {
        transition select((packet.lookahead<bit<16>>())[7:0]) {
            8w0xfd: parse_medium_name;
            8w0xfe: parse_big_name;
            8w0xff: parse_huge_name;
            default: parse_small_name;
        }
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<32>>(32w65536) pit_r;

    register<bit<32>>(32w512) section_r;

    register<bit<16>>(32w512) section_hash_r;

    register<bit<32>>(32w65536) cs_r;
    action storeNumOfComponents(bit<8> total) {
        meta.components = total;
    }
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action set_egr(bit<9> egress_spec) {
        standard_metadata.egress_port = egress_spec;
        meta.hasFIBentry = 8w1;
    }
    action set_interestegr() {
        standard_metadata.egress_port = 254;
        standard_metadata.bit_mcast = 0x8000000;
    }
    action computeNameHashes() {
        hash(meta.c1, HashAlgorithm.crc16, (bit<16>)0, { hdr.component1.tlv_value }, (bit<32>)65536);
        hash(meta.c2, HashAlgorithm.crc16, (bit<16>)0, { hdr.component1.tlv_value, hdr.component2.tlv_value }, (bit<32>)65536);
        hash(meta.c3, HashAlgorithm.crc16, (bit<16>)0, { hdr.component1.tlv_value, hdr.component2.tlv_value, hdr.component3.tlv_value }, (bit<32>)65536);
        hash(meta.c4, HashAlgorithm.crc16, (bit<16>)0, { hdr.component1.tlv_value, hdr.component2.tlv_value, hdr.component3.tlv_value, hdr.component4.tlv_value }, (bit<32>)65536);
    }
    action computeStoreTablesIndex() {
        hash(meta.name_hash, HashAlgorithm.crc16, (bit<16>)0, { hdr.component1.tlv_value, hdr.component2.tlv_value, hdr.component3.tlv_value, hdr.component4.tlv_value, hdr.component5.tlv_value }, (bit<32>)65536);
        computeNameHashes();
    }
    action readPit() {
        pit_r.read(meta.isInPIT, (bit<32>)meta.name_hash);
    }
    action readPitEntry() {
        readPit();
    }
    action cleanPitEntry() {
        readPit();
        pit_r.write((bit<32>)meta.name_hash, (bit<32>)0x0);
    }
    action readSection() {
        standard_metadata.egress_port = 254;
        section_r.read(standard_metadata.bit_mcast, (bit<32>)standard_metadata.ingress_port);
    }
    action writesection() {
        section_r.write((bit<32>)standard_metadata.ingress_port, standard_metadata.bit_mcast);
    }
    action readsection_hash() {
        section_hash_r.read(meta.name_hash, (bit<32>)standard_metadata.ingress_port);
    }
    action writesection_hash() {
        section_hash_r.write((bit<32>)standard_metadata.ingress_port, meta.name_hash);
    }
    action readCs() {
        cs_r.read(meta.isInCS, (bit<32>)meta.name_hash);
    }
    action readCsEntry() {
        readCs();
    }
    action addCstoMutist() {
        meta.isInPIT = meta.isInPIT| (bit<32>)(1 << 27);
    }
    action updateonlyCs() {
        cs_r.write((bit<32>)meta.name_hash, 32w1);
    }
    action updateCsEntry() {
        meta.isInPIT = meta.isInPIT | (bit<32>)(1 << 27);
        cs_r.write((bit<32>)meta.name_hash, 32w1);
    }
    action multicast() {
        standard_metadata.egress_port = 254;
        //standard_metadata.bit_mcast = 0x8fffffff;
        standard_metadata.bit_mcast = (bit<32>)meta.isInPIT ;
    }
    action updatePit_entry() {
        meta.ingress_tmp = (bit<8>)(meta.isInPIT & (bit<32>)(9w1 << (bit<8>)standard_metadata.ingress_port));
        meta.isInPIT = meta.isInPIT | (32w1 << (standard_metadata.ingress_port));
        pit_r.write((bit<32>)meta.name_hash, (bit<32>)meta.isInPIT);
    }
    table section_table {
        actions = {
            readSection;
            _drop;
        }
        key = {
            meta.hdr_ndnlpfragcount_flag: exact;
        }
        size = 2;
    }
    //table updatesection_table {
      //  actions = {
        //    writesection;
        //}
        //size = 2;
    //}
    //table sectionhashread_table {
      //  actions = {
        //    readsection_hash;
        //}
        //size = 2;
    //}
    //table sectionhashwrite_table {
      //  actions = {
        //    writesection_hash;
        //}
        //size = 2;
    //}
    table count_table {
        actions = {
            storeNumOfComponents;
            _drop;
        }
        key = {
            meta.hdr_component1_flag : exact;
            meta.hdr_component2_flag : exact;
            meta.hdr_component3_flag : exact;
            meta.hdr_component4_flag : exact;
            meta.hdr_component5_flag : exact;
        }
        size = 5;
    }
    table fib_table {
        actions = {
            set_egr;
            _drop;
        }
        key = {
            meta.components: exact;
            meta.c1        : exact;
            meta.c2        : exact;
            meta.c3        : exact;
            meta.c4        : exact;
            meta.name_hash : exact;
        }
    }
   // table interestcs_table {
     //   actions = {
    //        set_interestegr;
    //    }
    //    size = 2;
    //}
    //table hashName_table {
    //    actions = {
     //       computeStoreTablesIndex;
     //   }
    //    size = 2;
    //}
    table pit_table {
        actions = {
            readPitEntry;
            cleanPitEntry;
        }
        key = {
            meta.packetType: exact;
        }
        size = 2;
    }
    //table cs_table {
     //   actions = {
    //        readCsEntry;
     //   }
    //    size = 2;
    //}
    table updatecs_table {
        actions = {
            addCstoMutist;
            updateCsEntry;
        }
        key = {
            meta.hdr_ndnlpfragcount_flag : exact;
        }
        size = 2;
    }
    //table updateonlycs_table {
        //actions = {
            //updateonlyCs;
        //}
        //size = 2;
    //}
    //table routeData_table {
       // actions = {
       //     multicast;
        //}
        //size = 2;
   // }
    table updatePit_table {
        actions = {
            updatePit_entry;
            _drop;
        }
        key = {
            meta.hasFIBentry: exact;
        }
        size = 2;
    }
    //table updatehitcsPit_table {
    //    actions = {
     //       updatePit_entry;
     //   }
    //    size = 2;
    //}
    apply {
        if(hdr.ndnlpfragcount.isValid()){
            meta.hdr_ndnlpfragcount_flag = 1;
        }else{
            meta.hdr_ndnlpfragcount_flag = 0;
        }
        if(hdr.component1.isValid()){
            meta.hdr_component1_flag = 1;
        }else{
            meta.hdr_component1_flag = 0;
        }
        if(hdr.component2.isValid()){
            meta.hdr_component2_flag = 1;
        }else{
            meta.hdr_component2_flag = 0;
        }
        if(hdr.component3.isValid()){
            meta.hdr_component3_flag = 1;
        }else{
            meta.hdr_component3_flag = 0;
        }
        if(hdr.component4.isValid()){
            meta.hdr_component4_flag = 1;
        }else{
            meta.hdr_component4_flag = 0;
        }
        if(hdr.component5.isValid()){
            meta.hdr_component5_flag = 1;
        }else{
            meta.hdr_component5_flag = 0;
        }
        if (!hdr.component1.isValid()) {
            section_table.apply();
            if (meta.Count == meta.Index + 1) {
                readsection_hash();
                updateonlyCs();
            }
        } else {
            count_table.apply();
            computeStoreTablesIndex();
            pit_table.apply();
            if (meta.packetType == 8w0x5) {
                readCsEntry();
                if (meta.isInCS == 32w0) {
                    if (meta.isInPIT == 32w0) {
                        fib_table.apply();
                    }
                    updatePit_table.apply();
                } else {
                    set_interestegr();
                    updatePit_entry();
                }
            } else {
                updatecs_table.apply();
                //routeData_table.apply();
                multicast();
                if (hdr.ndnlpfragcount.isValid()) {
                    writesection();
                    writesection_hash();
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
        packet.emit(hdr.component1);
        packet.emit(hdr.component2);
        packet.emit(hdr.component3);
        packet.emit(hdr.component4);
        packet.emit(hdr.component5);
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

