/*****************************************************************************
 * @File Name: 
 * @Author: HongQiang
 * @EMail: hongqiang@comleader.com.cn
 * @Date: 2022-01-20 10:08:07
 * @LastEditTime: 2022-01-26 14:45:57
 *******************************************************************************/
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
Description: Macro definition and struct lcdata.
Author: Ian
Version: 1.0
Date: 2021.12.31
*****************************************************************************/

#ifndef __WITH_NIC_H_
#define __WITH_NIC_H_

#define PPK_NIC_VARIANT on

#include "dpdk_lib.h"
#include <stdbool.h>

#define PPK_BROADCAST_PORT 100
#ifndef KNI_STORAGE
#define KNI_STORAGE 0
#endif
#ifndef PPK_VLAN
#define PPK_VLAN 0
#endif
#define MAX_PKT_BURST 32      /* note: this equals to MBUF_TABLE_SIZE in dpdk_lib.h */
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MAX_PORTS 16

#define MCAST_CLONE_PORTS 2
#define MCAST_CLONE_SEGS 2

#define NB_PKT_MBUF 8192

#define HDR_MBUF_DATA_SIZE (2 * RTE_PKTMBUF_HEADROOM)
#define NB_HDR_MBUF (NB_PKT_MBUF * MAX_PORTS)

#define NB_CLONE_MBUF (NB_PKT_MBUF * MCAST_CLONE_PORTS * MCAST_CLONE_SEGS * 2)

// note: this much space MUST be able to hold all deparsed content
#define DEPARSE_BUFFER_SIZE 1024

#define PPK_PACKET_IN 255
#define MCAST_PORT 254

struct vlan_tag
{
    uint16_t type;
    uint16_t vid : 12;
    uint8_t cfi : 1;
    uint8_t pri : 3;
} vlan;
#define VLAN_SIZE sizeof(vlan)

struct lcore_data
{
    const uint64_t drain_tsc;
    uint64_t prev_tsc;

    struct lcore_conf *conf;

    packet *pkts_burst[MAX_PKT_BURST];
    unsigned nb_rx;

    bool is_valid;

    struct rte_mempool *mempool;
} * static_lcore;

#endif
