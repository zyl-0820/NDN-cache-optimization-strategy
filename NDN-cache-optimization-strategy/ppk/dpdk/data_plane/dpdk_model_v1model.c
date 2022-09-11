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

#include "dpdk_model_v1model.h"
#include "util_packet.h"
#include "des.h"

#include <rte_ip.h>

extern uint8_t *des_key;
extern uint16_t padding;
extern struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
int egress_port_field()
{
    return field_standard_metadata_t_egress_port;
}

int ingress_port_field()
{
    return field_standard_metadata_t_ingress_port;
}

int bit_port_field()
{
    return field_standard_metadata_t_bit_mcast;
}

void transfer_to_egress(packet_descriptor_t *pd)
{
    uint32_t res32;
    (void)res32;
#if PPK_VLAN
    MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_ethernet, field_ethernet_t_etherType, 0x0081);
    debug("       v1model :value of ethernet-type field  " T4LIT(% 08x) "\n", GET_INT32_AUTO_PACKET(pd, header_instance_ethernet, field_ethernet_t_etherType));
#endif
    // if (pd->headers[header_instance_ethernet].pointer != NULL){
    //     pd->is_emit_reordering = true;
    // }
    // int res32; // needed for the macro
    uint32_t val = GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_egress_spec);
    debug("       v1model :value of egress spec field  " T4LIT(% 08x) "\n", val);

    if (GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_egress_port) == NULL)
    {
        MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_egress_port, val);
    }
    debug("       v1model :value of egress port field  " T4LIT(% 08x) "\n", GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_egress_port));
}

int extract_egress_port(packet_descriptor_t *pd)
{
    return GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, egress_port_field());
}

int extract_ingress_port(packet_descriptor_t *pd)
{
    return GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, ingress_port_field());
}

int extract_bit_mcast(packet_descriptor_t *pd)
{
    uint32_t val = GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, bit_port_field());
    debug("      field standard_metadata.bit_mcast =   " T4LIT(% x) "\n", val);
    return GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, bit_port_field());
}

void set_handle_packet_metadata(packet_descriptor_t *pd, uint32_t portid)
{
    int res32; // needed for the macro
    MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, ingress_port_field(), portid);
}

extern uint16_t modbus_crc(unsigned char *p, int len);
void hash(unsigned char result, enum enum_HashAlgorithm algorithm, uint16_t base, struct uint8_buffer_s data, uint32_t max, SHORT_STDPARAMS)
{
    debug("    : Called extern " T4LIT(hash, extern) "\n");
    int res32;
    uint16_t hash = 0;
    if (algorithm == enum_HashAlgorithm_crc16)
    {
        hash = modbus_crc(data.buffer, data.buffer_size);
        if (max == 0)
        {
            MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_meta, result, base);
        }
        else
        {
            hash = hash % (max + base - 1);
            debug("       hash :  %x\n", hash);
            MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_meta, result, hash);
        }
    }
}
uint16_t modbus_crc(unsigned char *p, int len)
{
    uint16_t ret = 0xFFFF;
    int i = 0;
    int k = 0;

    for (i = 0; i < len; ++i)
    {
        ret ^= p[i];
        for (k = 0; k < 8; ++k)
        {
            ret = (ret & 0x01) ? ((ret >> 1) ^ 0xA001) : (ret >> 1);
        }
    }
    ret = ((ret & 0xFFFF) << 8) | ((ret & 0xFFFF) >> 8);
    return ret;
}
void verify_checksum(bool cond, struct uint8_buffer_s data, bitfield_handle_t cksum_field_handle, enum enum_HashAlgorithm algorithm, SHORT_STDPARAMS)
{
    debug("    : Called extern " T4LIT(verify_checksum, extern) "\n");
    uint32_t res32, current_cksum = 0, calculated_cksum = 0;
    if (cond)
    {
        if (algorithm == enum_HashAlgorithm_csum16)
        {
            calculated_cksum = rte_raw_cksum(data.buffer, data.buffer_size);
            calculated_cksum = (calculated_cksum == 0xffff) ? calculated_cksum : ((~calculated_cksum) & 0xffff);
            EXTRACT_INT32_BITS(cksum_field_handle, current_cksum)
        }

#ifdef PPK_DEBUG
        if (current_cksum == calculated_cksum)
        {
            debug("      : Packet checksum is " T4LIT(ok, success) ": " T4LIT(% 04x, bytes) "\n", current_cksum);
        }
        else
        {
            debug("    " T4LIT(!!, error) " Packet checksum is " T4LIT(wrong, error) ": " T4LIT(% 04x, bytes) ", calculated checksum is " T4LIT(% 04x, bytes) "\n", current_cksum, calculated_cksum);
        }
#endif

        if (unlikely(calculated_cksum != current_cksum))
        {
            MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_checksum_error, 1)
        }
    }
}

void update_checksum(bool cond, struct uint8_buffer_s data, bitfield_handle_t cksum_field_handle, enum enum_HashAlgorithm algorithm, SHORT_STDPARAMS)
{
    debug("    : Called extern " T4LIT(update_checksum, extern) "\n");

    uint32_t res32, calculated_cksum = 0;
    if (cond)
    {
        if (algorithm == enum_HashAlgorithm_csum16)
        {
            calculated_cksum = rte_raw_cksum(data.buffer, data.buffer_size);
            calculated_cksum = (calculated_cksum == 0xffff) ? calculated_cksum : ((~calculated_cksum) & 0xffff);
        }

        debug("       : Packet checksum " T4LIT(updated, status) " to " T4LIT(% 04x, bytes) "\n", calculated_cksum);

        // TODO temporarily disabled: this line modifies a lookup table's pointer instead of a checksum field
        // MODIFY_INT32_INT32_BITS(cksum_field_handle, calculated_cksum)
    }
}

void verify_checksum_offload(bitfield_handle_t cksum_field_handle, enum enum_HashAlgorithm algorithm, SHORT_STDPARAMS)
{
    debug("    : Called extern " T4LIT(verify_checksum_offload, extern) "\n");

    if ((pd->wrapper->ol_flags & PKT_RX_IP_CKSUM_BAD) != 0)
    {
        uint32_t res32;
        MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_checksum_error, 1)

        debug("       : Verifying packet checksum: " T4LIT(% 04x, bytes) "\n", res32);
    }
}

void update_checksum_offload(bitfield_handle_t cksum_field_handle, enum enum_HashAlgorithm algorithm, uint8_t len_l2, uint8_t len_l3, SHORT_STDPARAMS)
{
    debug("    : Called extern " T4LIT(update_checksum_offload, extern) "\n");

    pd->wrapper->l2_len = len_l2;
    pd->wrapper->l3_len = len_l3;
    pd->wrapper->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
    uint32_t res32;
    MODIFY_INT32_INT32_BITS(cksum_field_handle, 0)

    debug("       : Updating packet checksum (offload)\n");
    // TODO implement offload
}

void mark_to_drop(SHORT_STDPARAMS)
{
    debug("    : Called extern " T4LIT(mark_to_drop, extern) "\n");

    uint32_t res32;
    MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_drop, 1)

    debug("       : " T4LIT(standard_metadata, header) "." T4LIT(drop, field) " = " T4LIT(1, bytes) "\n");
}

void verify(bool check, enum error_error toSignal, SHORT_STDPARAMS)
{
    // TODO implement call to extern
    debug("    : Called extern " T4LIT(verify, extern) "\n");
}

void verify_checksum_with_payload(bool condition, struct uint8_buffer_s data, bitfield_handle_t checksum, enum enum_HashAlgorithm algo, SHORT_STDPARAMS)
{
    // TODO implement call to extern
    debug("    : Called extern " T4LIT(verify_checksum_with_payload, extern) "\n");
}

void update_checksum_with_payload(bool condition, struct uint8_buffer_s data, bitfield_handle_t checksum, enum enum_HashAlgorithm algo, SHORT_STDPARAMS)
{
    // TODO implement call to extern
    debug("    : Called extern " T4LIT(update_checksum_with_payload, extern) "\n");
}
#if 0
void encrypt_with_payload(SHORT_STDPARAMS) {
    uint64_t block_count = 0, number_of_blocks;
    uint8_t* data_block = (uint8_t*)malloc(8*sizeof(uint8_t));
    uint8_t* process_block = (uint8_t*)malloc(8*sizeof(uint8_t));
    key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

    generate_sub_keys(des_key, key_sets);
    number_of_blocks = pd->payload_length/8 + ((pd->payload_length%8)?1:0);
    uint8_t* pd_payload =  pd->data + pd->parsed_length;
    while (pd_payload < (pd->data + packet_length(pd))){
        memcpy(data_block, pd_payload, 8);
        block_count++;
        if(block_count == number_of_blocks) {
            padding = 8 - (pd->data + packet_length(pd) - pd_payload)%8;
            if(padding<8){
                memset((data_block + 8 - padding), (uint8_t)padding, padding);
            }

            process_message(data_block, process_block, key_sets, ENCRYPTION_MODE);
            memcpy(pd_payload, process_block, 8);
            if(padding == 8){
                memset(data_block, (uint8_t)padding, 8);
                process_message(data_block, process_block, key_sets, ENCRYPTION_MODE);
                memcpy(pd_payload, process_block, 8);
            }
            pd_payload +=8;
            rte_pktmbuf_append(pd->wrapper, padding);
        } else {
            process_message(data_block, process_block, key_sets, ENCRYPTION_MODE);
            memcpy(pd_payload, process_block, 8);
            pd_payload +=8;
        }// memset(data_block, 0, 8);
    }
    free(data_block);
    free(process_block);
    free(key_sets);
    debug("    : Called extern " T4LIT(encrypt_with_payload,extern) "\n");
    dbg_bytes(pd->data + pd->parsed_length, pd->payload_length, "    : " T4LIT(Payload,header) " is " T4LIT(%d) " bytes: ", pd->payload_length);
}


void decrypt_with_payload(SHORT_STDPARAMS){
    uint64_t block_count1 = 0, number_of_blocks1;
    uint8_t* data_block1 = (uint8_t*)malloc(8*sizeof(uint8_t));
    uint8_t* process_block1 = (uint8_t*)malloc(8*sizeof(uint8_t));
    key_set* key_sets1 = (key_set*)malloc(17*sizeof(key_set));

    generate_sub_keys(des_key, key_sets1);

    number_of_blocks1 = pd->payload_length/8 + ((pd->payload_length%8)?1:0);
    uint8_t* pd_payload =  pd->data + pd->parsed_length;
    while (pd_payload < (pd->data + packet_length(pd)))
    {
        memcpy(data_block1, pd_payload, 8);
        block_count1++;
        if(block_count1 == number_of_blocks1) {
	        process_message(data_block1, process_block1, key_sets1, DECRYPTION_MODE);
	        padding = process_block1[7];
	        if (padding < 8) {
                // memset(pd_payload, 0, 8);
            	memcpy(pd_payload, process_block1, 8 - padding);
                rte_pktmbuf_trim(pd->wrapper, padding);
                pd->payload_length -= padding;
	         }else{
                memcpy(pd_payload, process_block1, (pd->data + packet_length(pd)) - pd_payload);
             }
             pd_payload +=(8 - padding);
        }
	    else {
            // encypt mode = 1
            // decrpt mode = 0
            process_message(data_block1, process_block1, key_sets1, DECRYPTION_MODE);
            
            memcpy(pd_payload, process_block1, 8);
            pd_payload +=8;
        }
        // memset(data_block1, 0, 8);
    }
    free(data_block1);
    free(process_block1);
    free(key_sets1);
    // TODO implement call to extern
    debug("    : Called extern " T4LIT(decrypt_with_payload,extern) "\n");
    dbg_bytes(pd->data + pd->parsed_length, pd->payload_length, "    : " T4LIT(Payload,header) " is " T4LIT(%d) " bytes: ", pd->payload_length);
}
#endif
// void clone2(enum enum_CloneType type, uint32_t session, SHORT_STDPARAMS){
//     struct packet* neww_packet = clone_packet(pd, pktmbuf_pool[get_socketid(rte_lcore_id())]);
// }

// void clone3(enum enum_CloneType type, uint32_t session, struct uint8_buffer_s data, SHORT_STDPARAMS){
//     struct packet_descriptor_s clone_pd;
//     clone_pd.wrapper = clone_packet(pd, pktmbuf_pool[get_socketid(rte_lcore_id())]);
//     clone_pd.headers[header_instance_all_metadatas].pointer = data.buffer;
// }

//add pcap store
#include "pcap.h"
#include <stdio.h>

int write_file_header(FILE* fd, pcap_file_header *pcap_file_hdr){
    int ret = 0;
    if( fd < 0)
    return -1;
    ret = fwrite(pcap_file_hdr,sizeof(pcap_file_header),1,fd);
    if(ret != 1)
    return -1;
    return 0;
}

int write_header(FILE* fd, pcap_header *pcap_hdr){
    int ret = 0;
    if(fd<0)
    return -1;
    ret = fwrite(pcap_hdr,sizeof(pcap_hdr),1,fd);
    if(ret != 1)
    return -1;
    return 0;
}

int write_pbuf(FILE* fd, const char *buf, int len){
    int ret = 0;
    if(fd<0)
    return -1;
    ret = fwrite(buf,len,1,fd);
    if(ret != 1)
    return -1;
    return 0;
}

void encode_pcap(struct packet_descriptor_t* pd,FILE* f,const char* fname){
    debug("v1model :store_pcap \n");
    uint16_t major = 2;
    uint16_t minor = 4;
    pcap_file_header pcap_file_hdr;
    pcap_header pcap_hdr;
    timestamp pcap_time;
    char *buf = pd->data;
    uint32_t len = pd->payload_length;

    pcap_file_hdr.magic = 0xa1b2c3d4;
    pcap_file_hdr.major = major;
    pcap_file_hdr.minor = minor;
    pcap_file_hdr.thiszone = 0;
    pcap_file_hdr.sigfigs = 0;
    pcap_file_hdr.snaplen = 65535;
    pcap_file_hdr.linktype = 1;

    pcap_time.timestamp_s = 0;
    pcap_time.timestamp_ms = 0;

    pcap_hdr.caplen = len;
    pcap_hdr.len = len;

    bool ret = access("../log/pcap.pcap",0);
    if (ret != 0){
        FILE *fd;
        int ret = 0;
        fd = fopen("../log/pcap.pcap","wb+");
        if (fd == NULL){
            debug("error pcap fopen\n");
            return;
        }
        ret = write_file_header(fd,&pcap_file_hdr);
        if(ret == -1){
            debug("error pcap_file_hdr write\n");
            return;
        }
        fseek(fd,0,SEED_END);
        ret = write_header(fd,&pcap_hdr);
        if(ret == -1){
            debug("error pcap_hdr write\n");
            return;
        }
        fseek(fd,0,SEEK_END);
        ret = write_pbuf(fd,buf,len);
        if(ret == -1){
            debug("error buf write\n");
            return
        }
        fclose(fd);
        return;
    }else{
        FILE *fd_exist;
        int ret_e = 0;
        fd_exist = fopen("../log/pcap.pcap","ab+");
        if(fd_exist == NULL){
            debug("error exist_pcap error\n");
            return;
        }
        fseek(fd_exist,0,SEEK_END);
        ret_e =write_header(fd_exist,&pcap_hdr);
        if(ret_e == -1){
            debug("error pcap_exist_hdr write\n");
            return;
        }
        fseek(fd_exist,0,SEEK_END);
        ret_e = write_pbuf(fd_exist,buf,len);
        if (ret_e == -1){
            debug("error bug_exist write\n");
            return;
        }
        fclose(fd_exist);
        return;
    }
}

void store_pcap(packet_descriptor_t pd,const char* fname){
    FILE *f;
    if (fname == NULL){
        debug("   ::Error fname\n");
        return NULL;
    }
    if (fname[0] =='-' && fname[1] == '\0' ){
        f = stdout;
        fname = "standard output";
    }else{
        f = charset_fopen(fname, "wb");
        if (f == NULL ){
            debug("error create fname\n");
        }
    }
    return (encode_pcap(pd,f,fname));
}
 //add udef here
#include "../../udef/encrycard.c"
#include "../../udef/hash_tbl.c"
#include "../../udef/sa_tbl.c"