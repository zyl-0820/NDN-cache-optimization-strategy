// Copyright 2017 Eotvos Lorand University, Budapest, Hungary
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "dpdk_model_psa.h"

#include <rte_ip.h>
#include "actions.h"
#include "util.h"

extern struct all_metadatas_t all_metadatas;

void InternetChecksum_t_init() {
    debug(" :::: calling extern " T4LIT(InternetChecksum_t_init,extern) "\n");
}

void extern_InternetChecksum_clear() {
    debug(" :::: calling extern " T4LIT(extern_InternetChecksum_clear,extern) "\n");
}

void extern_InternetChecksum_add() {
    debug(" :::: calling extern " T4LIT(extern_InternetChecksum_add,extern) "\n");
}

void InternetChecksum_t_get() {
    debug(" :::: calling extern " T4LIT(InternetChecksum_t_get,extern) "\n");
}

void transfer_to_egress(packet_descriptor_t* pd) 
{
    /*not implemented*/
}

int extract_egress_port(packet_descriptor_t* pd) {
    return GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_instance_psa_ingress_output_metadata_egress_port);
}

int extract_ingress_port(packet_descriptor_t* pd) {
    return GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_instance_psa_ingress_parser_input_metadata_ingress_port);
}

void set_handle_packet_metadata(packet_descriptor_t* pd, uint32_t portid)
{
    int res32; // needed for the macro
    MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, field_instance_psa_ingress_parser_input_metadata_ingress_port, portid);
}

void verify_checksum(bool cond, struct uint8_buffer_s data, bitfield_handle_t cksum_field_handle, enum enum_PSA_HashAlgorithm_t algorithm, SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(verify_checksum,extern) "\n");
}

void update_checksum(bool cond, struct uint8_buffer_s data, bitfield_handle_t cksum_field_handle, enum enum_PSA_HashAlgorithm_t algorithm, SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(update_checksum,extern) "\n");
}

void verify_checksum_offload(bitfield_handle_t cksum_field_handle, enum enum_PSA_HashAlgorithm_t algorithm, SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(verify_checksum_offload,extern) "\n");
}

void update_checksum_offload(bitfield_handle_t cksum_field_handle, enum enum_PSA_HashAlgorithm_t algorithm, uint8_t len_l2, uint8_t len_l3, SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(update_checksum_offload,extern) "\n");
}

void mark_to_drop(SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(mark_to_drop,extern) "\n");

    uint32_t res32;
    MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_drop, 1)
}

void verify(bool check, enum error_error toSignal, SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(verify,extern) "\n");
}

void verify_checksum_with_payload(bool condition, struct uint8_buffer_s data, bitfield_handle_t checksum, enum enum_PSA_HashAlgorithm_t algo, SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(verify_checksum_with_payload,extern) "\n");
}

void update_checksum_with_payload(bool condition, struct uint8_buffer_s data, bitfield_handle_t checksum, enum enum_PSA_HashAlgorithm_t algo, SHORT_STDPARAMS) {
    debug(" :::: Calling extern " T4LIT(update_checksum_with_payload,extern) "\n");
}
