// Copyright 2018 Eotvos Lorand University, Budapest, Hungary
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
/*****************************************************************************
Copyright: 2020-2022, xindawangyu Tech. Co., Ltd.
File name: dpdk_nicon
Description: the file contains a wrapper for the DPDK interface and function called by main.c.
Author: Ian
Version: 1.0
Date: 2021.12.31
*****************************************************************************/
#include <rte_ethdev.h>
#include "dpdk_nicon.h"
#include "des.h"

/* get the physical socket_id of the specified lcore*/
extern int get_socketid(unsigned lcore_id);

/* defined in dpdk_lib_init_hw.c*/
extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* init rx queue of core, init the mbuf_pool,enable promiscuous model for ports */
extern void dpdk_init_nic();

/* NOTICE: deprecated since DPDK 18.05*/
extern uint8_t get_nb_ports();

/* header_pool for normal packet forwarding,clone_pool for clone and copy model*/
struct rte_mempool *header_pool, *clone_pool;

/* soft encrypttion uses des algorithm,generating the key and padding*/
uint8_t *des_key;
uint16_t padding;

/* defined in des.c*/
extern void generate_key(uint8_t *key);

/* defined in dpdk_lib.c*/
extern struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

/* Macro defined abcd consist of ipv4*/
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))

/* size of the key*/
#define DES_KEY_SIZE 8
// ------------------------------------------------------

/* Send burst of packets on an output interface */
static inline void send_burst(struct lcore_conf *conf, uint16_t n, uint8_t port)
{
    uint16_t queueid = conf->hw.tx_queue_id[port];
    struct rte_mbuf **m_table = (struct rte_mbuf **)conf->hw.tx_mbufs[port].m_table;

    int ret = rte_eth_tx_burst(port, queueid, m_table, n);
    if (unlikely(ret < n))
    {
        do
        {
            rte_pktmbuf_free(m_table[ret]);
        } while (++ret < n);
    }
}

void tx_burst_queue_drain(struct lcore_data *lcdata)
{
    uint64_t cur_tsc = rte_rdtsc();

    uint64_t diff_tsc = cur_tsc - lcdata->prev_tsc;
    if (unlikely(diff_tsc > lcdata->drain_tsc))
    {
        for (unsigned portid = 0; portid < get_nb_ports(); portid++)
        {
            if (lcdata->conf->hw.tx_mbufs[portid].len == 0)
                continue;

            send_burst(lcdata->conf,
                       lcdata->conf->hw.tx_mbufs[portid].len,
                       (uint8_t)portid);
            lcdata->conf->hw.tx_mbufs[portid].len = 0;
        }

        lcdata->prev_tsc = cur_tsc;
    }
}

// ------------------------------------------------------

static uint16_t
add_packet_to_queue(struct rte_mbuf *mbuf, uint8_t port, uint32_t lcore_id)
{
    struct lcore_conf *conf = &lcore_conf[lcore_id];
    uint16_t queue_length = conf->hw.tx_mbufs[port].len;
    conf->hw.tx_mbufs[port].m_table[queue_length] = mbuf;
    //杩欓噷搴旇鏄痟w.tx_mbufs[port].len澧炲姞锛屽師鏉ユ槸queue_length澧炲姞鍜岃繑鍥烇紝鏄竴涓嚱鏁板眬閮ㄥ彉閲忥紝娌＄敤
    conf->hw.tx_mbufs[port].len++;
    return conf->hw.tx_mbufs[port].len;
}

/* creating replicas of a packet for  */
static inline struct rte_mbuf *
mcast_out_pkt(struct rte_mbuf *pkt, int use_clone)
{
    struct rte_mbuf *hdr;

    debug("mcast_out_pkt new mbuf is needed...\n");
    /* Create new mbuf for the header. */
    if ((hdr = rte_pktmbuf_alloc(header_pool)) == NULL)
        return (NULL);

    debug("hdr is allocated\n");

    /* If requested, then make a new clone packet. */
    if (use_clone != 0 &&
        (pkt = rte_pktmbuf_clone(pkt, clone_pool)) == NULL)
    {
        rte_pktmbuf_free(hdr);
        return (NULL);
    }

    debug("setup ne header\n");

    /* prepend new header */
    hdr->next = pkt;

    /* update header's fields */
    hdr->pkt_len = (uint16_t)(hdr->data_len + pkt->pkt_len);
    hdr->nb_segs = (uint8_t)(pkt->nb_segs + 1);

    /* copy metadata from source packet*/
    hdr->port = pkt->port;
    hdr->vlan_tci = pkt->vlan_tci;
    hdr->vlan_tci_outer = pkt->vlan_tci_outer;
    hdr->tx_offload = pkt->tx_offload;
    hdr->hash = pkt->hash;

    hdr->ol_flags = pkt->ol_flags;

    __rte_mbuf_sanity_check(hdr, 1);
    return (hdr);
}

/*
TODO by Ian
鏋勯€犳姤鏂囧姞鍏ラ槦鍒椾腑
*/
static uint32_t g_src_ip = MAKE_IPV4_ADDR(10, 0, 0, 4);
static uint32_t g_dest_ip = MAKE_IPV4_ADDR(10, 0, 0, 5);

static void
fill_ethernet_header(struct rte_ether_hdr *hdr)
{
    struct rte_ether_addr s_addr = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}};
    struct rte_ether_addr d_addr = {{0x05, 0x04, 0x03, 0x02, 0x01, 0x00}};
    hdr->s_addr = s_addr;
    hdr->d_addr = d_addr;
    hdr->ether_type = rte_cpu_to_be_16(0x0800);
}

static void
fill_ipv4_header(struct rte_ipv4_hdr *hdr)
{
    hdr->version_ihl = (4 << 4) + 5;          // ipv4, length 5 (*4)
    hdr->type_of_service = 0;                 // No Diffserv
    hdr->total_length = rte_cpu_to_be_16(40); // tcp 20
    hdr->packet_id = rte_cpu_to_be_16(5462);  // set random
    hdr->fragment_offset = rte_cpu_to_be_16(0);
    hdr->time_to_live = 64;
    hdr->next_proto_id = 6; // tcp
    hdr->hdr_checksum = rte_cpu_to_be_16(25295);
    hdr->src_addr = rte_cpu_to_be_32(0xC0A80001); // 192.168.0.1
    hdr->dst_addr = rte_cpu_to_be_32(0x01010101); // 1.1.1.1
}

static void
fill_tcp_header(struct rte_tcp_hdr *hdr)
{
    hdr->src_port = rte_cpu_to_be_16(0x162E);
    hdr->dst_port = rte_cpu_to_be_16(0x04d2);
    hdr->sent_seq = rte_cpu_to_be_32(0);
    hdr->recv_ack = rte_cpu_to_be_32(0);
    hdr->data_off = 0;
    hdr->tcp_flags = 0;
    hdr->rx_win = rte_cpu_to_be_16(16);
    hdr->cksum = rte_cpu_to_be_16(0);
    hdr->tcp_urp = rte_cpu_to_be_16(0);
}

// void
// tx_vlan_set(portid_t port_id, uint16_t vlan_id)
// {
// 	int vlan_offload;
// 	if (port_id_is_invalid(port_id, ENABLED_WARN))
// 		return;
// 	if (vlan_id_is_invalid(vlan_id))
// 		return;

// 	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);
// 	if (vlan_offload & ETH_VLAN_EXTEND_OFFLOAD) {
// 		printf("Error, as QinQ has been enabled.\n");
// 		return;
// 	}

// 	tx_vlan_reset(port_id);
// 	ports[port_id].tx_ol_flags |= TESTPMD_TX_OFFLOAD_INSERT_VLAN;
// 	ports[port_id].tx_vlan_id = vlan_id;
//     struct rte_vlan_hdr;
// }
// struct rte_ether_hdr *ether_h;
// struct rte_ipv4_hdr *ipv4_h;
// struct rte_tcp_hdr *tcp_h;
// ether_h = (struct rte_ether_hdr *) rte_pktmbuf_append(buff, sizeof(struct rte_ether_hdr));
// fill_ethernet_header(ether_h);

// ipv4_h = (struct rte_ipv4_hdr *) rte_pktmbuf_append(buff, sizeof(struct rte_ipv4_hdr));
// fill_ipv4_header(ipv4_h);

// tcp_h = (struct rte_tcp_hdr *) rte_pktmbuf_append(buff, sizeof(struct rte_tcp_hdr));
// fill_tcp_header(tcp_h);
// ---

void send_packetout_from_controller(struct p4_ctrl_msg *ctrl_m)
{
    printf("Dummy callback - payload_name:%s\n\n\n", ctrl_m->packet);
    uint32_t lcore_id = 1;
    struct rte_mbuf *buff;
    struct rte_mbuf **m = &buff;
    debug("-----------------------1--------------------\n");
    buff = rte_pktmbuf_alloc(header_pool);

    uint8_t *data = (uint8_t *)rte_pktmbuf_append(buff, ctrl_m->len);
    strcpy(data, ctrl_m->packet);
    debug("-----------------------2--------------------\n");
    // (*m)->vlan_tci = 0x457;
    // int value = rte_vlan_insert(m);
    // int egress_port = ctrl_m->metadata[0];
    int egress_port = 2;
    debug("-----------------------3----------%d----------\n", egress_port);
    uint16_t queue_length = add_packet_to_queue(buff, egress_port, lcore_id);
    debug("-----------------------4--------------------\n");
    void rte_pktmbuf_free(buff);
}
// ------------------------------------------------------

static void dpdk_send_packet(struct rte_mbuf *mbuf, uint8_t port, uint32_t lcore_id)
{
    struct lcore_conf *conf = &lcore_conf[lcore_id];
    uint16_t queue_length = add_packet_to_queue(mbuf, port, lcore_id);

    if (unlikely(queue_length == MAX_PKT_BURST))
    {
        debug("    :: BURST SENDING DPDK PACKETS - port:%d\n", port);
        send_burst(conf, MAX_PKT_BURST, port);
        queue_length = 0;
    }

    conf->hw.tx_mbufs[port].len = queue_length;
}

/* Enqueue a single packet, and send burst if queue is filled */
void send_single_packet(struct lcore_data *lcdata, packet_descriptor_t *pd, packet *pkt, int egress_port, int ingress_port, bool send_clone)
{
    uint32_t lcore_id = rte_lcore_id();
    struct rte_mbuf *mbuf = (struct rte_mbuf *)pkt;
#if PPK_VLAN
    // by ian
    uint8_t *data = rte_pktmbuf_mtod(mbuf, void *);
    vlan.pri = 0;
    vlan.cfi = 0;
    debug("       v1model :value of egress port field  " T4LIT(% 08x) "\n", egress_port);
    vlan.vid = (0xfff & egress_port) + (GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_ingress_port) * 64);
    uint16_t vlantype32 = (uint16_t)GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_instance_type);
    debug("       v1model :value of ethernet-type field  " T4LIT(% 08x) "\n", vlantype32);
    vlan.type = rte_cpu_to_be_16(vlantype32);
    uint32_t vlan_of = *(uint32_t *)&vlan;
    uint32_t vlan1 = rte_cpu_to_be_32(vlan_of);
    // uint8_t* mtod = rte_pktmbuf_prepend(mbuf,sizeof(vlan));
    // memcpy(mtod, (mtod+4), 14);
    // memcpy(data+18, data+14, rte_pktmbuf_pkt_len(mbuf)-18);
    memcpy(data + 14, &vlan1, sizeof(vlan));
    int fix_egress_port = egress_port % 2;
    dbg_bytes(rte_pktmbuf_mtod(mbuf, uint8_t *), rte_pktmbuf_pkt_len(mbuf), "   " T4LIT(>>>>, outgoing) " " T4LIT(Emitting, outgoing) " packet on port " T4LIT(% d, port) " (" T4LIT(% d) " bytes): ", fix_egress_port, rte_pktmbuf_pkt_len(mbuf));
    dpdk_send_packet(mbuf, fix_egress_port, lcore_id);
#else
    dpdk_send_packet(mbuf, egress_port, lcore_id);
#endif
}

// ------------------------------------------------------

void init_queues(struct lcore_data *lcdata)
{
    for (unsigned i = 0; i < lcdata->conf->hw.n_rx_queue; i++)
    {
        unsigned portid = lcdata->conf->hw.rx_queue_list[i].port_id;
        uint8_t queueid = lcdata->conf->hw.rx_queue_list[i].queue_id;
        RTE_LOG(INFO, P4_FWD, " -- lcoreid=%u portid=%u rxqueueid=%hhu\n", rte_lcore_id(), portid, queueid);
    }
}

struct lcore_data init_lcore_data()
{
    struct lcore_data lcdata = {
        .drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US,
        .prev_tsc = 0,

        .conf = &lcore_conf[rte_lcore_id()],
        .mempool = pktmbuf_pool[get_socketid(rte_lcore_id())], // TODO: Check for MULTI-SOCKET CASE !!!!

        .is_valid = lcdata.conf->hw.n_rx_queue != 0,
    };

    if (lcdata.is_valid)
    {
        RTE_LOG(INFO, P4_FWD, "entering main loop on lcore %u\n", rte_lcore_id());

        init_queues(&lcdata);
    }
    else
    {
        RTE_LOG(INFO, P4_FWD, "lcore %u has nothing to do\n", rte_lcore_id());
    }

    return lcdata;
}

// ------------------------------------------------------

bool core_is_working(struct lcore_data *lcdata)
{
    return true;
}

bool is_packet_handled(packet_descriptor_t *pd, struct lcore_data *lcdata)
{
    return true;
}

bool receive_packet(packet_descriptor_t *pd, struct lcore_data *lcdata, unsigned pkt_idx)
{
    packet *p = lcdata->pkts_burst[pkt_idx];
    rte_prefetch0(rte_pktmbuf_mtod(p, void *));
    pd->data = rte_pktmbuf_mtod(p, uint8_t *);
    pd->wrapper = p;

    return true;
}

void free_packet(packet_descriptor_t *pd)
{
    rte_pktmbuf_free(pd->wrapper);
}

void init_storage()
{
    /* Needed for L2 multicasting - e.g. acting as a hub
        cloning headers and sometimes packet data*/
    header_pool = rte_pktmbuf_pool_create("header_pool", NB_HDR_MBUF, 32,
                                          0, HDR_MBUF_DATA_SIZE, rte_socket_id());

    if (header_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init header mbuf pool\n");

    clone_pool = rte_pktmbuf_pool_create("clone_pool", NB_CLONE_MBUF, 32,
                                         0, 0, rte_socket_id());

    if (clone_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init clone mbuf pool\n");
}

/* generate encrypt key and store file,then decryption can use the file*/
void init_encypt_key()
{
    static FILE *key_file;
    key_file = fopen("./key.txt", "wb");
    if (!key_file)
    {
        rte_exit(EXIT_FAILURE, "Could not open file to write key.\n");
    }
    // unsigned int iseed = (unsigned int)time(NULL);
    // srand (iseed);
    des_key = (uint8_t *)malloc(8 * sizeof(uint8_t));
    generate_key(des_key);
    short int bytes_written;
    bytes_written = fwrite(des_key, 1, DES_KEY_SIZE, key_file);
    if (bytes_written != DES_KEY_SIZE)
    {
        fclose(key_file);
        free(des_key);
        rte_exit(EXIT_FAILURE, "Error writing key to output file.\n");
    }
    fclose(key_file);
}

void main_loop_pre_rx(struct lcore_data *lcdata)
{
    tx_burst_queue_drain(lcdata);
}

void main_loop_post_rx(struct lcore_data *lcdata)
{
}

void main_loop_post_single_rx(struct lcore_data *lcdata, bool got_packet)
{
}

uint32_t get_portid(struct lcore_data *lcdata, unsigned queue_idx)
{
    return lcdata->conf->hw.rx_queue_list[queue_idx].port_id;
}

void main_loop_rx_group(struct lcore_data *lcdata, unsigned queue_idx)
{
    uint8_t queue_id = lcdata->conf->hw.rx_queue_list[queue_idx].queue_id;
    uint8_t port_id = lcdata->conf->hw.rx_queue_list[queue_idx].port_id;
#if KNI_STORAGE
    unsigned num = 0;
    unsigned nb_nic_rx = 0;
    uint8_t kni_lcore_id = rte_lcore_id();
    /* port_id is same as Interest package entry of flow table  */
    if (port_id == 0)
    {
        uint8_t kni_queue_id = kni_lcore_id;
        struct rte_mbuf *kni_pkts_burst[MAX_PKT_BURST];
        num = my_kni_egress(kni_pkts_burst, 3, MAX_PKT_BURST);
        for (unsigned i = 0; i < num; i++)
        {
            lcdata->pkts_burst[i] = kni_pkts_burst[i];
        }
        my_kni_burst_free_mbufs(&kni_pkts_burst[0], num);
        lcdata->nb_rx = num;
        lcdata->nb_rx += rte_eth_rx_burst((uint8_t)get_portid(lcdata, queue_idx), queue_id, &(lcdata->pkts_burst[num]), (MAX_PKT_BURST - num));
    }
    else
    {
        lcdata->nb_rx = rte_eth_rx_burst((uint8_t)get_portid(lcdata, queue_idx), queue_id, lcdata->pkts_burst, MAX_PKT_BURST);
    }
#else
    lcdata->nb_rx = rte_eth_rx_burst((uint8_t)get_portid(lcdata, queue_idx), queue_id, lcdata->pkts_burst, MAX_PKT_BURST);
#endif
}

unsigned get_pkt_count_in_group(struct lcore_data *lcdata)
{
    return lcdata->nb_rx;
}

unsigned get_queue_count(struct lcore_data *lcdata)
{
    return lcdata->conf->hw.n_rx_queue;
}

void initialize_nic()
{
    dpdk_init_nic();
}

int launch_count()
{
    return 1;
}

void ppk_abnormal_exit(int retval, int idx)
{
    debug(T4LIT(Abnormal exit, error) ", code " T4LIT(% d) ".\n", retval);
}

void ppk_after_launch(int idx)
{
    debug(T4LIT(Execution done., success) "\n");
}

int ppk_normal_exit()
{
    debug(T4LIT(Normal exit., success) "\n");
    return 0;
}

void ppk_pre_launch(int idx)
{
}

void ppk_post_launch(int idx)
{
}

extern uint32_t enabled_port_mask;
uint32_t get_port_mask()
{
    return enabled_port_mask;
}

extern uint8_t get_nb_ports();
uint8_t get_port_count()
{
    return get_nb_ports();
}
