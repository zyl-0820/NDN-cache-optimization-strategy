#ifndef __ENCRYCARD_H__
#define __ENCRYCARD_H__


/* º¯ÊıÉêÃ÷ */
extern int zhijiang_init_crypto_device(void);
extern unsigned int IPSec(struct rte_mbuf *in_mbuf, unsigned int spi, unsigned int srcip, unsigned int dstip, unsigned int coreid);
extern unsigned int unIPSec(struct rte_mbuf *in_mbuf, unsigned int coreid);


#endif
