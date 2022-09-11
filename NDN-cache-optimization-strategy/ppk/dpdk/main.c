/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*****************************************************************************
Copyright: 2020-2022, xindawangyu Tech. Co., Ltd.
File name: main
Description: It's main Function of PPK(Polymorphic Processing Kit). A large portion of the code in this file comes from main.c in the 
l3fwd example of DPDK.
Author: Ian
Version: 1.0
Date: 2021.12.31
*****************************************************************************/

#include "dpdk_lib.h"
#include <rte_ethdev.h>
#include "gen_include.h"
#include "dpdk_nicon.h"

/* NIC checkout  */
#ifndef PPK_NIC_VARIANT
#error The NIC variant is undefined
#endif

/* cflags parameter of noeal */
#ifdef PPK_SUPPRESS_EAL
    #include <unistd.h>
    #include <stdio.h>
#endif

/* dpdk init command line arguments*/
extern void initialize_args(int argc, char **argv);

/* dpdk init nic*/
extern void initialize_nic();

/* init tables info*/
extern int init_tables();

/* TODO DBG model store stateful memory*/
extern int init_memories();

/* flush three struct tables:exact LPM ternary
Reset all hash structure, by zeroing all entries*/
extern int flush_tables();

/* Number of P4 programs loaded*/
extern int launch_count();

/* if abnormal exit,echo launch count number*/
extern void ppk_abnormal_exit(int retval, int idx);

/* TODO different architected preprocessing*/
extern void ppk_pre_launch(int idx);

/* TODO PPK ending processing*/
extern void ppk_post_launch(int idx);

extern int ppk_normal_exit();

/* defined in the generated file controlplane.c,
build controlplane backend,init dev_mgr_ptr .etc*/
extern void init_control_plane();

/* defined in the generated file dataplane.c,
process received packets*/
extern void handle_packet(packet_descriptor_t *pd, lookup_table_t **tables, parser_state_t *pstate, uint32_t portid);

/* defined separately for each example*/
extern bool core_is_working(struct lcore_data *lcdata);
extern bool receive_packet(packet_descriptor_t *pd, struct lcore_data *lcdata, unsigned pkt_idx);
extern void free_packet(packet_descriptor_t *pd);
extern bool is_packet_handled(packet_descriptor_t *pd, struct lcore_data *lcdata);
extern void init_storage();
extern void init_encypt_key();
extern void main_loop_pre_rx(struct lcore_data *lcdata);
extern void main_loop_post_rx(struct lcore_data *lcdata);
extern void main_loop_post_single_rx(struct lcore_data *lcdata, bool got_packet);
extern uint32_t get_portid(struct lcore_data *lcdata, unsigned queue_idx);
extern void main_loop_rx_group(struct lcore_data *lcdata, unsigned queue_idx);
extern unsigned get_pkt_count_in_group(struct lcore_data *lcdata);
extern unsigned get_queue_count(struct lcore_data *lcdata);
extern void send_single_packet(struct lcore_data *lcdata, packet_descriptor_t *pd, packet *pkt, int egress_port, int ingress_port);
extern void send_broadcast_packet(struct lcore_data *lcdata, packet_descriptor_t *pd, int egress_port, int ingress_port);
extern struct lcore_data init_lcore_data();
extern packet *clone_packet(packet *pd, struct rte_mempool *mempool);
extern packet *copy_packet(packet *pd, struct rte_mempool *mempool, uint32_t offset, uint32_t length);
extern void init_parser_state(parser_state_t *);

/* KNI:Kernel NIC Interface,packet id thrown back to the linux kernel*/
#if KNI_STORAGE
extern int kni_loop();
extern void my_kni_ingress(struct rte_mbuf **pkts, unsigned nb_rx, uint16_t kni_port_id);
extern unsigned my_kni_egress(struct rte_mbuf **mbufs, uint16_t kni_port_id, uint16_t max_rx_kni_pkt);
extern void kni_free();
extern void my_kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num);
#endif
//=============================================================================

/* set the enabled port*/
extern uint32_t get_port_mask();

/* get numbers of available ports*/
extern uint8_t get_port_count();

/*************************************************
Function: get_broadcast_port_msg
Description: print broadcast ports.
Calls: sprintf
Called By: send_packet
Input: result:print string、
       ingress_port:begin port
Output: NULL
*************************************************/
void get_broadcast_port_msg(char result[256], int ingress_port)
{
    uint8_t nb_ports = get_port_count();
    uint32_t port_mask = get_port_mask();

    char *result_ptr = result;
    bool is_first_printed_port = true;
    for (uint8_t portidx = 0; portidx < RTE_MAX_ETHPORTS; ++portidx)
    {
        if (portidx == ingress_port)
        {
            continue;
        }

        bool is_port_disabled = (port_mask & (1 << portidx)) == 0;
        if (is_port_disabled)
            continue;

        int printed_bytes = sprintf(result_ptr, "%s" T4LIT(% d, port), is_first_printed_port ? "" : ", ", portidx);
        result_ptr += printed_bytes;
        is_first_printed_port = false;
    }
}

/*************************************************
Function: broadcast_packet
Description: broadcast packet.
Calls: send_single_packet
Called By: send_packet
Input: lcdata:description of lcore data,include tsc、valid、lcore configure struct、mempool of dpdk、
       data and numbers of receive packet.
       pd:description of packet,include mbuf of dpdk、packet data and packet header .etc
       egress_port:out port of pipeline
       ingress_port:input port of pipeline
Output: NULL
*************************************************/
void broadcast_packet(struct lcore_data *lcdata, packet_descriptor_t *pd, int egress_port, int ingress_port)
{
    uint8_t nb_ports = get_port_count();
    uint32_t port_mask = get_port_mask();
    uint8_t nb_port = 0;
    for (uint8_t portidx = 0; nb_port < nb_ports - 1 && portidx < RTE_MAX_ETHPORTS; ++portidx)
    {
        if (portidx == ingress_port)
        {
            continue;
        }
        bool is_port_disabled = (port_mask & (1 << portidx)) == 0;
        if (is_port_disabled)
            continue;
        packet *pkt_out = (nb_port < nb_ports) ? clone_packet(pd->wrapper, lcdata->mempool) : pd->wrapper;
        send_single_packet(lcdata, pd, pkt_out, portidx, ingress_port);
        nb_port++;
    }
    if (unlikely(nb_port != nb_ports - 1))
    {
        debug(" " T4LIT(!!!!, error) " " T4LIT(Wrong port count, error) ": " T4LIT(% d) " ports should be present, but only " T4LIT(% d) " found\n", nb_ports, nb_port);
    }
}

/* PPK_VLAN is for 7132 platform*/
#if PPK_VLAN
void bitmcast_packet(struct lcore_data *lcdata, packet_descriptor_t *pd, int egress_port, int ingress_port, int bit_mcast)
{
    uint8_t nb_ports = 27;
    uint8_t nb_port = 0;
    for (uint8_t portidx = 1; (nb_port < nb_ports) && portidx < RTE_MAX_ETHPORTS + 1; ++portidx)
    {
        if (ingress_port == portidx)
        {
            nb_port++;
            continue;
        }
        if (nb_port == 26)
        {
            packet *pkt_out = copy_packet(pd->wrapper, lcdata->mempool, 0, UINT32_MAX);
            send_single_packet(lcdata, pd, pkt_out, 39, ingress_port);
            nb_port++;
            continue;
        }
        if (((bit_mcast & (0x1 << (portidx - 1))) >> (portidx - 1)) == 0)
        {
            nb_port++;
            continue;
        }
        packet *pkt_out = (nb_port < nb_ports) ? copy_packet(pd->wrapper, lcdata->mempool, 0, UINT32_MAX) : pd->wrapper;
        send_single_packet(lcdata, pd, pkt_out, portidx, ingress_port);
        nb_port++;
    }
    free_packet(pd);
    if (unlikely(nb_port != nb_ports))
    {
        debug(" " T4LIT(!!!!, error) " " T4LIT(Wrong port count, error) ": " T4LIT(% d) " ports should be present, but only " T4LIT(% d) " found\n", nb_ports, nb_port);
    }
}
#else
/*************************************************
Function: bitmcast_packet
Description: mcast packet by bits,such as 0xff will send packet from 8 ports.
Calls: send_single_packet
Called By: send_packet
Input: lcdata:description of lcore data,include tsc、valid、lcore configure struct、mempool of dpdk、
       data and numbers of receive packet.
       pd:description of packet,include mbuf of dpdk、packet data and packet header .etc
       egress_port:out port of pipeline
       ingress_port:input port of pipeline
       bitcast:mcast by bits
Output: NULL
*************************************************/
void bitmcast_packet(struct lcore_data *lcdata, packet_descriptor_t *pd, int egress_port, int ingress_port, uint32_t bit_mcast)
{
    uint8_t nb_ports = get_port_count();
    uint32_t port_mask = get_port_mask();
    uint8_t nb_port = 0;
#if KNI_STORAGE
    if ((bit_mcast & 0x8000000) != 0)
    {
        my_kni_ingress(&(pd->wrapper), 1, 3);
    }
#endif
    for (uint8_t portidx = 0; (nb_port < (nb_ports - 1)) && portidx < RTE_MAX_ETHPORTS; ++portidx)
    {
        bool is_port_disabled = (port_mask & (0x1 << portidx)) == 0;
        if (is_port_disabled)
            continue;
        /* judge whether the number portidx bit of bit_mcast is 0, if true then continue*/
        if (((bit_mcast & (0x1 << portidx)) >> portidx) == 0)
        {
            nb_port++;
            continue;
        }
        packet *pkt_out = (nb_port < nb_ports) ? clone_packet(pd->wrapper, lcdata->mempool) : pd->wrapper;
        send_single_packet(lcdata, pd, pkt_out, portidx, ingress_port);
        nb_port++;
    }
    free_packet(pd);
    if (unlikely(nb_port != nb_ports - 1))
    {
        debug(" " T4LIT(!!!!, error) " " T4LIT(Wrong port count, error) ": " T4LIT(% d) " ports should be present, but only " T4LIT(% d) " found\n", nb_ports, nb_port);
    }
}

#endif

/*************************************************
Function: send_packet
Description: Enqueue a single packet, and send burst if queue is filled
Calls: broadcast_packet/async_packetin/bitmcast_packet/send_single_packet
Called By: do_single_tx
Input: lcdata:description of lcore data,include tsc、valid、lcore configure struct、mempool of dpdk、
       data and numbers of receive packet.
       pd:description of packet,include mbuf of dpdk、packet data and packet header .etc
       egress_port:out port of pipeline
       ingress_port:input port of pipeline
       bitcast:mcast by bits
Output: NULL
*************************************************/
void send_packet(struct lcore_data *lcdata, packet_descriptor_t *pd, int egress_port, int ingress_port, uint32_t bitcast)
{
    uint32_t lcore_id = rte_lcore_id();
    struct rte_mbuf *mbuf = (struct rte_mbuf *)pd->wrapper;
    int len = rte_pktmbuf_pkt_len(mbuf);
    if (unlikely(egress_port == PPK_BROADCAST_PORT))
    {
#ifdef  PPK_DEBUG
        char ports_msg[256];
        get_broadcast_port_msg(ports_msg, ingress_port);
        dbg_bytes(rte_pktmbuf_mtod(mbuf, uint8_t *), rte_pktmbuf_pkt_len(mbuf), "   " T4LIT(<<, outgoing) " " T4LIT(Broadcasting, outgoing) " packet from port " T4LIT(% d, port) " to all other ports (%s) (" T4LIT(% d) " bytes): ", ingress_port, ports_msg, rte_pktmbuf_pkt_len(mbuf));
#endif
        broadcast_packet(lcdata, pd, egress_port, ingress_port);
    }
    else if (unlikely(egress_port == PPK_PACKET_IN))
    {
        /* insert vlan before send packet-in*/
        debug("egress_port == PPK_PACKET_IN\n");
        uint8_t *data = rte_pktmbuf_mtod(mbuf, void *);
        uint16_t packetin_vlantype = (uint16_t)GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_instance_type);
        memcpy(data + 14, &packetin_vlantype, VLAN_SIZE);
        async_packetin(data, len);
    }
    else if (unlikely(egress_port == MCAST_PORT))
    {
        bitmcast_packet(lcdata, pd, egress_port, ingress_port, bitcast);
    }
    else
    {
        dbg_bytes(rte_pktmbuf_mtod(mbuf, uint8_t *), rte_pktmbuf_pkt_len(mbuf), "   " T4LIT(<<, outgoing) " " T4LIT(Emitting, outgoing) " packet on port " T4LIT(% d, port) " (" T4LIT(% d) " bytes): ", egress_port, rte_pktmbuf_pkt_len(mbuf));
        send_single_packet(lcdata, pd, pd->wrapper, egress_port, ingress_port);
    }
}

/*************************************************
Function: do_single_tx
Description: send one packet from tx queue
Calls: free_packet/send_packet
Called By: do_single_rx
Input: lcdata:description of lcore data,include tsc、valid、lcore configure struct、mempool of dpdk、
       data and numbers of receive packet.
       pd:description of packet,include mbuf of dpdk、packet data and packet header .etc
       queue_idx:rx queue
       pkt_idx:Number of the rx queue
Output: NULL
*************************************************/
void do_single_tx(struct lcore_data *lcdata, packet_descriptor_t *pd, unsigned queue_idx, unsigned pkt_idx)
{
    if (unlikely(GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_drop)))
    {
        debug(" " T4LIT(XXXX, status) " " T4LIT(Dropping, status) " packet\n");
        free_packet(pd);
    }
    else
    {
        debug(" " T4LIT(< < < <, outgoing) " " T4LIT(Egressing, outgoing) " packet\n");

        int egress_port = extract_egress_port(pd);
        int ingress_port = extract_ingress_port(pd);
        uint32_t bitmcast = extract_bit_mcast(pd);
        send_packet(lcdata, pd, egress_port, ingress_port, bitmcast);
    }
}

/*************************************************
Function: do_single_rx
Description: recive one packet from queue
Calls: receive_packet/init_parser_state/handle_packet/do_single_tx
Called By: do_rx
Input: lcdata:description of lcore data,include tsc、valid、lcore configure struct、mempool of dpdk、
       data and numbers of receive packet.
       pd:description of packet,include mbuf of dpdk、packet data and packet header .etc
       queue_idx:rx queue
       pkt_idx:Number of the rx queue
Output: packet handle process
Others: one by one handle each packet of every queue
*************************************************/
void do_single_rx(struct lcore_data *lcdata, packet_descriptor_t *pd, unsigned queue_idx, unsigned pkt_idx)
{
    bool got_packet = receive_packet(pd, lcdata, pkt_idx);
    if (got_packet)
    {
        if (likely(is_packet_handled(pd, lcdata)))
        {
            init_parser_state(&(lcdata->conf->state.parser_state));
            handle_packet(pd, lcdata->conf->state.tables, &(lcdata->conf->state.parser_state), get_portid(lcdata, queue_idx));
            while (GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_recirculate_flag))
            {
                init_parser_state(&(lcdata->conf->state.parser_state));
                handle_packet(pd, lcdata->conf->state.tables, &(lcdata->conf->state.parser_state), get_portid(lcdata, queue_idx));
            }

            do_single_tx(lcdata, pd, queue_idx, pkt_idx);
        }
    }
    main_loop_post_single_rx(lcdata, got_packet);
}

/*************************************************
Function: do_rx
Description: recive packet function
Calls: get_queue_count/main_loop_rx_group/get_pkt_count_in_group/do_single_rx
Called By: dpdk_main_loop
Input: lcdata:description of lcore data,include tsc、valid、lcore configure struct、mempool of dpdk、
       data and numbers of receive packet.
       pd:description of packet,include mbuf of dpdk、packet data and packet header .etc
Output: NULL
Others: while core is working, it is a cycle.
*************************************************/
void do_rx(struct lcore_data *lcdata, packet_descriptor_t *pd)
{
    unsigned queue_count = get_queue_count(lcdata);
    for (unsigned queue_idx = 0; queue_idx < queue_count; queue_idx++)
    {
        main_loop_rx_group(lcdata, queue_idx);

        unsigned pkt_count = get_pkt_count_in_group(lcdata);
        for (unsigned pkt_idx = 0; pkt_idx < pkt_count; pkt_idx++)
        {
            do_single_rx(lcdata, pd, queue_idx, pkt_idx);
        }
    }
}

/*************************************************
Function: dpdk_main_loop
Description:  function of each lcore perform
Calls: init_lcore_data/init_dataplane/main_loop_pre_rx/do_rx/main_loop_post_rx
Called By: launch_one_lcore
Input: NULL
Output: valid of lcdata
*************************************************/
bool dpdk_main_loop()
{
    struct lcore_data lcdata = init_lcore_data();
#if KNI_STORAGE
    if (!lcdata.is_valid)
    {
        kni_loop();
        return true;
    }
#else
    if (!lcdata.is_valid)
    {
        return false;
    }
#endif

    packet_descriptor_t pd;
    init_dataplane(&pd, lcdata.conf->state.tables);

    while (core_is_working(&lcdata))
    {
        main_loop_pre_rx(&lcdata);
        do_rx(&lcdata, &pd);
        main_loop_post_rx(&lcdata);
    }
    return lcdata.is_valid;
}

static int
launch_one_lcore(__attribute__((unused)) void *dummy)
{
    bool success = dpdk_main_loop();
    return success ? 0 : -1;
}

/* each lcore perform function:launch_one_lcore*/
int launch_dpdk()
{
    rte_eal_mp_remote_launch(launch_one_lcore, NULL, CALL_MASTER);
    unsigned lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }
#if KNI_STORAGE
    kni_free();
#endif
    return 0;
}

/* encryption card*/
extern int zhijiang_init_crypto_device();
extern int alg_test(uint32_t flag);

int main(int argc, char **argv)
{
    /* printf thread*/
    debug("Init switch\n");

    /* init KNI and eal*/
    initialize_args(argc, argv);

    /* use DPDK-Pdump to capture packets*/
    rte_pdump_init(NULL);
    initialize_nic();
    zhijiang_init_crypto_device();
    int launch_count = launch_count();
    for (int i = 0; i < launch_count; ++i)
    {
        debug("Init execution\n");
        init_tables();

        /* init dpdk mempool*/
        init_storage();

        init_memories();
        debug(" " T4LIT(:: ::, incoming) " Init control plane connection\n");
        init_control_plane();
        
        /* generate the key of soft-encrypt*/
        init_encypt_key();
        ppk_pre_launch(i);

        int retval = launch_dpdk();
        if (retval < 0)
        {
            ppk_abnormal_exit(retval, i);
            return retval;
        }
        ppk_post_launch(i);
        flush_tables();
    }
    return ppk_normal_exit();
}
