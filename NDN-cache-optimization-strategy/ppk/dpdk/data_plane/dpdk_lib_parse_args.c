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

#include "dpdk_nicon.h"
#if KNI_STORAGE   
// This file is included directly from `dpdk_lib.c`.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include "dpdk_nicon.h"
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD                  1024

/* Number of TX ring descriptors */
#define NB_TXD                  1024

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400

#define KNI_MAX_KTHREAD 32
/*
 * Structure of port parameters
 */

struct kni_port_params {
	uint16_t port_id;/* Port ID */
	unsigned lcore_rx; /* lcore ID for RX */
	unsigned lcore_tx; /* lcore ID for TX */
	uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint32_t nb_kni; /* Number of KNI devices to be created */
	unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
	struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
} __rte_cache_aligned;

static struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

/* Mempool for mbufs */
static struct rte_mempool * kni_pktmbuf_pool = NULL;

/* Mask of enabled ports */
static uint32_t ports_mask = 0;
/* Ports set in promiscuous mode off by default. */
static int promiscuous_on = 1;
/* Monitor link status continually. off by default. */
static int monitor_links=1;

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
	/* number of pkts received from NIC, and sent to KNI */
	uint64_t rx_packets;

	/* number of pkts received from NIC, but failed to send to KNI */
	uint64_t rx_dropped;

	/* number of pkts received from KNI, and sent to NIC */
	uint64_t tx_packets;

	/* number of pkts received from KNI, but failed to send to NIC */
	uint64_t tx_dropped;
};

/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t kni_pause = RTE_ATOMIC32_INIT(0);

/* Print out statistics on packets handled */
static void print_stats(void)
{
	uint16_t i;

	printf("\n**KNI example application statistics**\n"
	       "======  ==============  ============  ============  ============  ============\n"
	       " Port    Lcore(RX/TX)    rx_packets    rx_dropped    tx_packets    tx_dropped\n"
	       "------  --------------  ------------  ------------  ------------  ------------\n");
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!kni_port_params_array[i])
			continue;

		printf("%7d %10u/%2u %13"PRIu64" %13"PRIu64" %13"PRIu64" "
							"%13"PRIu64"\n", i,
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->lcore_tx,
						kni_stats[i].rx_packets,
						kni_stats[i].rx_dropped,
						kni_stats[i].tx_packets,
						kni_stats[i].tx_dropped);
	}
	printf("======  ==============  ============  ============  ============  ============\n");

	fflush(stdout);
}

/* Custom handling of signals to handle stats and kni processing */
static void signal_handler(int signum)
{
	/* When we receive a USR1 signal, print stats */
	if (signum == SIGUSR1) {
		print_stats();
	}

	/* When we receive a USR2 signal, reset stats */
	if (signum == SIGUSR2) {
		memset(&kni_stats, 0, sizeof(kni_stats));
		printf("\n** Statistics have been reset **\n");
		return;
	}

	/* When we receive a RTMIN or SIGINT signal, stop kni processing */
	if (signum == SIGRTMIN || signum == SIGINT){
		printf("\nSIGRTMIN/SIGINT received. KNI processing stopping.\n");
		rte_atomic32_inc(&kni_stop);
		return;
        }
}

static void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}
void my_kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}
/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static void kni_ingress(struct kni_port_params *p)
{
	uint8_t i;
	uint16_t port_id;
	unsigned nb_rx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from eth\n");
			return;
		}
		/* Burst tx to kni */
		num = rte_kni_tx_burst(p->kni[i], pkts_burst, nb_rx);
		if (num)
			kni_stats[port_id].rx_packets += num;

		rte_kni_handle_request(p->kni[i]);
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
			kni_stats[port_id].rx_dropped += nb_rx - num;
		}
	}
}
// To do :将数据包 pkts发送通过kni发送至系统内核
void my_kni_ingress(struct rte_mbuf **pkts,unsigned nb_rx,uint16_t kni_port_id)
{
	uint8_t i;
	uint16_t port_id;
	unsigned num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct kni_port_params *p=kni_port_params_array[kni_port_id];
	if (p == NULL)
		return;
	for (i = 0; i < nb_rx; i++)
		pkts_burst[i] = pkts[i];
	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from eth\n");
			return;
		}
		/* Burst tx to kni */
		num = rte_kni_tx_burst(p->kni[i], pkts_burst, nb_rx);
		if (num)
			kni_stats[port_id].rx_packets += num;
		}
		rte_kni_handle_request(p->kni[i]);
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
			kni_stats[port_id].rx_dropped += nb_rx - num;
		}
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
unsigned  my_kni_egress(struct rte_mbuf **mbufs,uint16_t kni_port_id)
{
	uint8_t i;
	uint16_t port_id;
	unsigned num;
	//unsigned nb_tx;
	uint32_t nb_kni;
	//struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct kni_port_params *p=kni_port_params_array[kni_port_id];
	uint8_t lcore_id = rte_lcore_id();
	uint8_t queue_id = lcore_id;
	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni[i], (void **)mbufs, PKT_BURST_SZ);
		if (unlikely(num > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from KNI\n");
			return;
		}
		/* Burst tx to eth */
	/*	nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t)num);
		nb_tx = rte_eth_tx_burst(0, queue_id, pkts_burst, (uint16_t)num);
		if (nb_tx)
			kni_stats[port_id].tx_packets += nb_tx;
		//printf("ssz recevie %d pkts from kni ,and send to eth %d\n",num,nb_tx);
		if (unlikely(nb_tx < num)) {*/
			/* Free mbufs not tx to NIC */
	/*		kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
			kni_stats[port_id].tx_dropped += num - nb_tx;
		}*/
	}
	//printf("%d %d\n",pkts_burst,num);
	return num;
}
static void kni_egress(struct kni_port_params *p)
{
	uint8_t i;
	uint16_t port_id;
	unsigned nb_tx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
		if (unlikely(num > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from KNI\n");
			return;
		}
		/* Burst tx to eth */
		nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t)num);
		if (nb_tx)
			kni_stats[port_id].tx_packets += nb_tx;
		if (unlikely(nb_tx < num)) {
			/* Free mbufs not tx to NIC */
			kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
			kni_stats[port_id].tx_dropped += num - nb_tx;
		}
	}
}

int kni_loop(){
	
	uint16_t i;
	int32_t f_stop;
	int32_t f_pause;
	const unsigned lcore_id = rte_lcore_id();
	enum lcore_rxtx {
		LCORE_NONE,
		LCORE_RX,
		LCORE_TX,
		LCORE_MAX
	};
	enum lcore_rxtx flag = LCORE_NONE;

	RTE_ETH_FOREACH_DEV(i) {
		if (!kni_port_params_array[i])
			continue;
		if (kni_port_params_array[i]->lcore_rx == (uint8_t)lcore_id) {
			flag = LCORE_RX;
			break;
		} else if (kni_port_params_array[i]->lcore_tx ==(uint8_t)lcore_id) {
			flag = LCORE_TX;
			break;
		}
	}
	

	if (flag == LCORE_RX) {
		RTE_LOG(INFO, APP, "Lcore %u is reading from port %d and i is %d\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id,i);
		while (1) {
			f_stop = rte_atomic32_read(&kni_stop);
			f_pause = rte_atomic32_read(&kni_pause);
			if (f_stop)
				break;
			if (f_pause)
				continue;
			kni_ingress(kni_port_params_array[i]);
		}
	} 
	/*else if (flag == LCORE_TX) {
		RTE_LOG(INFO, APP, "Lcore %u is writing to port %d\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);
		while (1) {
			f_stop = rte_atomic32_read(&kni_stop);
			f_pause = rte_atomic32_read(&kni_pause);
			if (f_stop)
				break;
			if (f_pause)
				continue;
			kni_egress(kni_port_params_array[i]);
		}
	}*/
	else
		RTE_LOG(INFO, APP, "Lcore %u has nothing to do\n", lcore_id);

	return 0;
}


/* Display usage instructions */
static void kni_print_usage(const char *prgname)
{
	RTE_LOG(INFO, APP, "\nUsage: %s [EAL options] -- -p PORTMASK -P -m "
		   "[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
		   "[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
		   "    -p PORTMASk for kni: hex bitmask of ports to use\n"
		   "    -k PORTMASk for ppk: hex bitmask of ports to use\n"
		   "    -P : enable promiscuous mode\n"
		   "    -m : enable monitoring of port carrier state\n"
		   "    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
		   "port and lcore configurations\n",
	           prgname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint32_t parse_unsigned(const char *portmask)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return (uint32_t)num;
}

static void print_config(void)
{
	uint32_t i, j;
	struct kni_port_params **p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, APP, "Port ID: %d\n", p[i]->port_id);
		RTE_LOG(DEBUG, APP, "Rx lcore ID: %u, Tx lcore ID: %u\n",
					p[i]->lcore_rx, p[i]->lcore_tx);
		for (j = 0; j < p[i]->nb_lcore_k; j++)
			RTE_LOG(DEBUG, APP, "Kernel thread lcore ID: %u\n",
							p[i]->lcore_k[j]);
	}
}

static int parse_config(const char *arg)
{
	const char *p, *p0 = arg;
	char s[256], *end;
	unsigned size;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_LCORE_RX,
		FLD_LCORE_TX,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, j, nb_token;
	char *str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];
	uint16_t port_id, nb_kni_port_params = 0;

	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
	while (((p = strchr(p0, '(')) != NULL) &&
		nb_kni_port_params < RTE_MAX_ETHPORTS) {
		p++;
		if ((p0 = strchr(p, ')')) == NULL)
			goto fail;
		size = p0 - p;
		if (size >= sizeof(s)) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		snprintf(s, sizeof(s), "%.*s", size, p);
		nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
		if (nb_token <= FLD_LCORE_TX) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		for (i = 0; i < nb_token; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i]) {
				printf("Invalid config parameters\n");
				goto fail;
			}
		}

		i = 0;
		port_id = int_fld[i++];
		if (port_id >= RTE_MAX_ETHPORTS) {
			printf("Port ID %d could not exceed the maximum %d\n",
						port_id, RTE_MAX_ETHPORTS);
			goto fail;
		}
		if (kni_port_params_array[port_id]) {
			printf("Port %d has been configured\n", port_id);
			goto fail;
		}
		kni_port_params_array[port_id] =
			rte_zmalloc("KNI_port_params",
				    sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
		kni_port_params_array[port_id]->port_id = port_id;
		kni_port_params_array[port_id]->lcore_rx =
					(uint8_t)int_fld[i++];
		kni_port_params_array[port_id]->lcore_tx =
					(uint8_t)int_fld[i++];
		if (kni_port_params_array[port_id]->lcore_rx >= RTE_MAX_LCORE ||
		kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
			printf("lcore_rx %u or lcore_tx %u ID could not "
						"exceed the maximum %u\n",
				kni_port_params_array[port_id]->lcore_rx,
				kni_port_params_array[port_id]->lcore_tx,
						(unsigned)RTE_MAX_LCORE);
			goto fail;
		}
		for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
			kni_port_params_array[port_id]->lcore_k[j] =
						(uint8_t)int_fld[i];
		kni_port_params_array[port_id]->nb_lcore_k = j;
	}
	print_config();

	return 0;

fail:
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}
	}

	return -1;
}

static int validate_parameters(uint32_t portmask)
{
	uint32_t i;

	if (!portmask) {
		printf("No port configured in port mask\n");
		return -1;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
			(!(portmask & (1 << i)) && kni_port_params_array[i]))
			rte_exit(EXIT_FAILURE, "portmask is not consistent "
				"to port ids specified in --config\n");

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_rx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d receiving not enabled\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_tx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d transmitting not enabled\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);

	}

	return 0;
}

/* Initialize KNI subsystem */
static void init_kni(void)
{

	unsigned int num_of_kni_ports = 0, i;
	struct kni_port_params **params = kni_port_params_array;

	/* Calculate the maximum number of KNI interfaces that will be used */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			num_of_kni_ports += (params[i]->nb_lcore_k ?
				params[i]->nb_lcore_k : 1);
		}
	}
	/* num_of_kni_ports means that the maximum number of KNI interfaces that can coexist concurrently*/
	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
}


/* Initialise a single port on an Ethernet device */
static void init_port(uint16_t port)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	uint16_t nb_txd = NB_TXD;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_conf local_port_conf = port_conf;

	/* Initialise device and RX/TX queues */
	RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
	fflush(stdout);
 
	ret = rte_eth_dev_info_get(port, &dev_info);

	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port, strerror(-ret));

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	ret = rte_eth_dev_configure(port, 1, 1, &local_port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
		            (unsigned)port, ret);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned)port, ret);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;

	ret = rte_eth_rx_queue_setup(port, 0, nb_rxd,
		rte_eth_dev_socket_id(port), &rxq_conf, kni_pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
				"port%u (%d)\n", (unsigned)port, ret);

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port, 0, nb_txd,
		rte_eth_dev_socket_id(port), &txq_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
				"port%u (%d)\n", (unsigned)port, ret);

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
						(unsigned)port, ret);

	if (promiscuous_on) {
		ret = rte_eth_promiscuous_enable(port);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Could not enable promiscuous mode for port%u: %s\n",
				port, rte_strerror(-ret));
	}
}


/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up - speed %uMbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
	if (kni == NULL || link == NULL)
		return;

	if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
		RTE_LOG(INFO, APP, "%s NIC Link is Up %d Mbps %s %s.\n",
			rte_kni_get_name(kni),
			link->link_speed,
			link->link_autoneg ?  "(AutoNeg)" : "(Fixed)",
			link->link_duplex ?  "Full Duplex" : "Half Duplex");
	} else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
		RTE_LOG(INFO, APP, "%s NIC Link is Down.\n",
			rte_kni_get_name(kni));
	}
}

/*
 * Monitor the link status of all ports and update the
 * corresponding KNI interface(s)
 */
static void *monitor_all_ports_link_status(void *arg)
{
	uint16_t portid;
	struct rte_eth_link link;
	unsigned int i;
	struct kni_port_params **p = kni_port_params_array;
	int prev;
	(void) arg;
	int ret;

	while (monitor_links) {
		rte_delay_ms(500);
		RTE_ETH_FOREACH_DEV(portid) {
			if ((ports_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				RTE_LOG(ERR, APP,
					"Get link failed (port %u): %s\n",
					portid, rte_strerror(-ret));
				continue;
			}
			for (i = 0; i < p[portid]->nb_kni; i++) {
				prev = rte_kni_update_link(p[portid]->kni[i],
						link.link_status);
				log_link_state(p[portid]->kni[i], prev, &link);
			}
		}
	}
	return NULL;
}

static int kni_change_mtu_(uint16_t port_id, unsigned int new_mtu)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	uint16_t nb_txd = NB_TXD;
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > RTE_ETHER_MAX_LEN)
		conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
							KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned int)port_id,
				ret);

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0) {
		RTE_LOG(ERR, APP,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

		return ret;
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
		rte_eth_dev_socket_id(port_id), &rxq_conf, kni_pktmbuf_pool);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n",
				port_id);
		return ret;
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
		rte_eth_dev_socket_id(port_id), &txq_conf);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to setup Tx queue of port %d\n",
				port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

/* Callback for request of changing MTU */
static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
	int ret;

	rte_atomic32_inc(&kni_pause);
	ret =  kni_change_mtu_(port_id, new_mtu);
	rte_atomic32_dec(&kni_pause);

	return ret;
}

/* Callback for request of configuring network interface up/down */
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	rte_atomic32_inc(&kni_pause);

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	rte_atomic32_dec(&kni_pause);

	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);

	return ret;
}

static void print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
	RTE_LOG(INFO, APP, "\t%s%s\n", name, buf);
}

/* Callback for request of configuring mac address */
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure mac address of %d\n", port_id);
	print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					(struct rte_ether_addr *)mac_addr);
	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to config mac_addr for port %d\n",
			port_id);

	return ret;
}

static int kni_alloc(uint16_t port_id)
{
	uint8_t i;
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct kni_port_params **params = kni_port_params_array;
	int ret;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	params[port_id]->nb_kni = params[port_id]->nb_lcore_k ?
				params[port_id]->nb_lcore_k : 1;

	for (i = 0; i < params[port_id]->nb_kni; i++) {
		/* Clear conf at first */
		memset(&conf, 0, sizeof(conf));
		if (params[port_id]->nb_lcore_k) {
			snprintf(conf.name, RTE_KNI_NAMESIZE,
					"vEth%u_%u", port_id, i);
			conf.core_id = params[port_id]->lcore_k[i];
			conf.force_bind = 1;
		} else
			snprintf(conf.name, RTE_KNI_NAMESIZE,
						"vEth%u", port_id);
		conf.group_id = port_id;
		conf.mbuf_size = MAX_PACKET_SZ;
		/*
		 * The first KNI device associated to a port
		 * is the master, for multiple kernel thread
		 * environment.
		 */
		if (i == 0) {
			struct rte_kni_ops ops;
			struct rte_eth_dev_info dev_info;

			ret = rte_eth_dev_info_get(port_id, &dev_info);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					port_id, strerror(-ret));

			/* Get the interface default mac address */
			ret = rte_eth_macaddr_get(port_id,
				(struct rte_ether_addr *)&conf.mac_addr);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Failed to get MAC address (port %u): %s\n",
					port_id, rte_strerror(-ret));

			rte_eth_dev_get_mtu(port_id, &conf.mtu);

			conf.min_mtu = dev_info.min_mtu;
			conf.max_mtu = dev_info.max_mtu;

			memset(&ops, 0, sizeof(ops));
			ops.port_id = port_id;
			ops.change_mtu = kni_change_mtu;
			ops.config_network_if = kni_config_network_interface;
			ops.config_mac_address = kni_config_mac_address;

			kni = rte_kni_alloc(kni_pktmbuf_pool, &conf, &ops);
		} else
			kni = rte_kni_alloc(kni_pktmbuf_pool, &conf, NULL);

		if (!kni)
			rte_exit(EXIT_FAILURE, "Fail to create kni for "
						"port: %d\n", port_id);
		params[port_id]->kni[i] = kni;
	}

	return 0;
}

static int kni_free_kni(uint16_t port_id)
{
	uint8_t i;
	struct kni_port_params **p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	for (i = 0; i < p[port_id]->nb_kni; i++) {
		if (rte_kni_release(p[port_id]->kni[i]))
			printf("Fail to release kni\n");
		p[port_id]->kni[i] = NULL;
	}
	rte_eth_dev_stop(port_id);

	return 0;
}
void kni_free(){
	unsigned i;
	uint16_t port;
	RTE_ETH_FOREACH_DEV(port) {
		if (!(ports_mask & (1 << port)))
			continue;
		kni_free_kni(port);
	}
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}
}
#endif

static void print_usage(const char *prgname)
{
    printf ("%s [EAL options] -- -p PORTMASK -P"
        "  [--config (port,queue,lcore)[,(port,queue,lcore]]"
        "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
        "  -P : enable promiscuous mode\n"
        "  --config (port,queue,lcore): rx queues configuration\n"
        "  --no-numa: optional, disable numa awareness\n"
        " which max packet len is PKTLEN in decimal (64-9600)\n"
        "  --hash-entry-num: specify the hash entry number in hexadecimal to be setup\n",
        prgname);
}

static int parse_max_pkt_len(const char *pktlen)
{
    char *end = NULL;
    unsigned long len;

    /* parse decimal string */
    len = strtoul(pktlen, &end, 10);
    if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (len == 0)
        return -1;

    return len;
}

static int parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

// Note: sets nb_lcore_params and lcore_params.
static int parse_lcore_params(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];

    nb_lcore_params = 0;

    while ((p = strchr(p0,'(')) != NULL) {
        ++p;
        if((p0 = strchr(p,')')) == NULL)
            return -1;

        unsigned size = p0 - p;
        if(size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (int i = 0; i < _NUM_FLD; i++){
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            // printf("exceeded max number of lcore params: %hu\n", nb_lcore_params);
            return -1;
        }
        lcore_params[nb_lcore_params].port_id = (uint8_t)int_fld[FLD_PORT];
        lcore_params[nb_lcore_params].queue_id = (uint8_t)int_fld[FLD_QUEUE];
        lcore_params[nb_lcore_params].lcore_id = (uint8_t)int_fld[FLD_LCORE];
        ++nb_lcore_params;
    }
    return 0;
}

extern int numa_on;
extern int check_lcore_params();

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {CMD_LINE_OPT_CONFIG,         1, 0, 0},
        {CMD_LINE_OPT_NO_NUMA,        0, 0, 0},
        {CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, 0},
        {NULL,                        0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:P",lgopts, 
						&option_index)) != EOF) {
        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                printf("invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;
        case 'P':
            printf("Promiscuous mode on by default\n");
            break;

        /* long options */
        case 0:
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_CONFIG,
                sizeof (CMD_LINE_OPT_CONFIG))) {
                ret = parse_lcore_params(optarg);
                if (ret) {
                    printf("invalid config\n");
                    print_usage(prgname);
                    return -1;
                }
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_NO_NUMA,
                sizeof(CMD_LINE_OPT_NO_NUMA))) {
                printf("numa is disabled \n");
                numa_on = 0;
            }
            break;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}
#if KNI_STORAGE
#define CMD_LINE_OPT_CONFIG_ppk "config-ppk"
#define CMDLINE_OPT_CONFIG_kni  "config-kni"
/* Parse the arguments given in the command line of the application */
static int kni_parse_args(int argc, char **argv)
{
	int opt, longindex, ret = 0;
	const char *prgname = argv[0];
	static struct option longopts[] = {	
		{CMDLINE_OPT_CONFIG_kni, required_argument, NULL, 0},
		{CMD_LINE_OPT_CONFIG_ppk,     1, 0, 0},
        {CMD_LINE_OPT_NO_NUMA,        0, 0, 0},
        {CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, 0},
		{NULL, 0, NULL, 0}
	};

	/* Disable printing messages within getopt() */
	opterr = 0;

	/* Parse command line */
	while ((opt = getopt_long(argc, argv, "p:k:Pm", longopts,
						&longindex)) != EOF) {
		switch (opt) {
		case 'p':
			ports_mask = parse_unsigned(optarg);
			printf("ssz ports_mask:0x%hx\n",ports_mask);
			break;
		case 'k':
			enabled_port_mask = parse_unsigned(optarg);
			printf("ssz enable_port_mask:0x%hx\n",enabled_port_mask);
            if (enabled_port_mask == 0) {
                printf("invalid portmask\n");
                kni_print_usage(prgname);
            }
			break;
		case 'P':
			promiscuous_on = 1;
			break;
		case 'm':
			monitor_links = 1;
			break;
		case 0:
			if (!strncmp(longopts[longindex].name,
				     CMDLINE_OPT_CONFIG_kni,
				     sizeof(CMDLINE_OPT_CONFIG_kni))) {
				ret = parse_config(optarg);
				if (ret) {
					printf("Invalid config\n");
					kni_print_usage(prgname);
					return -1;
				}
			}
			 if (!strncmp(longopts[longindex].name, CMD_LINE_OPT_CONFIG_ppk,
                sizeof (CMD_LINE_OPT_CONFIG_ppk))) {
                ret = parse_lcore_params(optarg);
                if (ret) {
                    printf("invalid config\n");
                    kni_print_usage(prgname);
                    return -1;
                }
            }
            if (!strncmp(longopts[longindex].name, CMD_LINE_OPT_NO_NUMA,
                sizeof(CMD_LINE_OPT_NO_NUMA))) {
                printf("numa is disabled \n");
                numa_on = 0;
            }
            break;
		default:
			kni_print_usage(prgname);
			rte_exit(EXIT_FAILURE, "Invalid option specified\n");
		}
	}
	/* Check that options were parsed ok */
	if (validate_parameters(ports_mask) < 0) {
		kni_print_usage(prgname);
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");
	}

	return ret;
}
#endif
void initialize_args(int argc, char **argv)
{
#if KNI_STORAGE    
	uint16_t nb_sys_ports, port;
	unsigned i;
	unsigned lcore_id;
	void *retval;
	pthread_t kni_link_tid;
	int pid;

#endif
    /* Initialise EAL */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
    argc -= ret;
    argv += ret;

    /* parse application arguments (after the EAL ones) */
#if KNI_STORAGE  		
	ret = kni_parse_args(argc, argv);
#else
    ret = parse_args(argc, argv);
#endif	
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

#if KNI_STORAGE 
    /* Create the mbuf pool */
	kni_pktmbuf_pool = rte_pktmbuf_pool_create("kni_mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (kni_pktmbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialise kni mbuf pool\n");
		return -1;
	}

	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	/* Check if the configured port ID is valid */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i] && !rte_eth_dev_is_valid_port(i))
			rte_exit(EXIT_FAILURE, "Configured invalid "
						"port ID %u\n", i);

	/* Initialize KNI subsystem */
	init_kni();

	/* Initialise each port */
	/*RTE_ETH_FOREACH_DEV is a macro to iterate over all enabled and ownerless ethdev ports*/
	RTE_ETH_FOREACH_DEV(port) {
		/* Skip ports that are not enabled */
		if (!(ports_mask & (1 << port)))
			continue;
		init_port(port);

		if (port >= RTE_MAX_ETHPORTS)
			rte_exit(EXIT_FAILURE, "Can not use more than "
				"%d ports for kni\n", RTE_MAX_ETHPORTS);

		kni_alloc(port);
	}
	check_all_ports_link_status(ports_mask);

	pid = getpid();
	RTE_LOG(INFO, APP, "========================\n");
	RTE_LOG(INFO, APP, "KNI Running\n");
	RTE_LOG(INFO, APP, "kill -SIGUSR1 %d\n", pid);
	RTE_LOG(INFO, APP, "    Show KNI Statistics.\n");
	RTE_LOG(INFO, APP, "kill -SIGUSR2 %d\n", pid);
	RTE_LOG(INFO, APP, "    Zero KNI Statistics.\n");
	RTE_LOG(INFO, APP, "========================\n");
	fflush(stdout);
 #endif	
}
