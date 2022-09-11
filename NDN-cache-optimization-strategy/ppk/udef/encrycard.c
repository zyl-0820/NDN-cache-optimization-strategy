#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_eal.h>
#include <rte_cryptodev.h>

#include "encrycard.h"
#include "hash_tbl.h"
#include "sa_tbl.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

struct getcpu_cache
{
        unsigned long blob[128/sizeof(long)];
};

int getcpu(unsigned *cpu,unsigned *node,struct getcpu_cache *tcache)
{

        return syscall(SYS_getcpu,cpu,node,tcache);
}

#define ZHIJIANG_READ(X) 1

typedef struct rsp_context_s{
    uint32_t dev_id;
    uint32_t socket_id;
    uint32_t qp_id;
    uint32_t op;
    uint32_t c_size;
	uint32_t c_offset;
	uint32_t a_size;
	uint32_t a_offset;
	uint32_t proto;
	uint8_t *iv;
	
}rsp_context_t;

enum rsp_op_e{
     GET_DEV_INFO       = 0,    
     AES_128_CBC        ,    
     AES_128_GCM        ,    
     AES_256_CBC        ,    
     AES_256_GCM        ,    
     SM4_CBC            = 5,    
     SM4_GCM            ,    
     SM1_CBC            = 7,    
     RSA_1024_SIGN      ,    
     RSA_1024_SIGN_CRT  ,    
     RSA_1024_VERI      ,    
     RSA_1024_ENC       ,   
     RSA_1024_DEC       ,   
     RSA_2048_SIGN      ,   
     RSA_2048_SIGN_CRT  ,   
     RSA_2048_VERI      ,   
     RSA_2048_ENC       ,   
     RSA_2048_DEC       ,   
     ECC_256R1_SIGN     ,   
     ECC_256R1_VERIFY   ,   
     ECC_SM2_SIGN       ,   
     ECC_SM2_VERIFY     ,   
     BULK_TRNG_GEN      ,
     BULK_SHA1_HMAC     ,
     BULK_SHA256_HMAC   ,
     BULK_SM3_HMAC      = 25,
     AES_128_CBC_SHA1   ,
     AES_128_CBC_SHA256 ,
     AES_256_CBC_SHA1   ,
     AES_256_CBC_SHA256 ,
     SM4_SM3            = 30,
     SM1_SM3            = 31,
     SHA1_AES_128_CBC   ,
     SHA256_AES_128_CBC ,
     SHA1_AES_256_CBC   ,
     SHA256_AES_256_CBC ,
     SM3_SM4            = 36,
     SM3_SM1            = 37,
     ALGO_MAX            ,
};

#define IPV4_PROTOCOL    		0x4
#define MAX_MBUF_SIZE       	4096
#define RSP_MAX_DEPTH       	1024
#define RSP_CACHE_SIZE      	128
#define MAC_HEAD_LEN 			14
#define MAC_TYPE_LEN 			2
#define MAC_TAIL_LEN 			4
#define ESP_TAIL_LEN 			2
#define ESP_HEADER_LEN 			8
#define IPV4_PROTOCOL 			0x4
#define GEO_PROTOCOL 			0x5
#define AH_SEQUENCE_OFFSET   	8
#define NORMAL_IP_HEADER_LEN  	20
#define ESP_PROTOCOL 			50
#define AUTHEN_DATA_LENGTH   	12
#define MAX_TTL   				255
#define ENCRY_CARD_DEVICE 		"0000:0a:00.0_rsp_s10_sym"

#define  MSG_DISPLAY     debug
//#define  MSG_DISPLAY(x)   


#define IPSEC_ENCAP_ESP_TAIL(addr,len)\
	do{\
		unsigned int esp_tail_encap_idx;\
		for(esp_tail_encap_idx = 0; esp_tail_encap_idx < len; esp_tail_encap_idx++){\
			*(unsigned char*)(addr + esp_tail_encap_idx) = esp_tail_encap_idx + 1;\
		}\
	}while(0)


#define IPSEC_ENCAP_ESP_IV(pDwIv,len)\
	do{\
		unsigned int esp_iv_encap_idx;\
		unsigned char esp_iv_encap_rand;\
		srand((unsigned)time(NULL)); \
        for(esp_iv_encap_idx = 0; esp_iv_encap_idx < len; esp_iv_encap_idx++){\
			esp_iv_encap_rand = rand() % 256;\
            *(unsigned char*)(pDwIv + esp_iv_encap_idx) = esp_iv_encap_rand;\
        }\
	}while(0)

		

#define GLUE_GB08(p) ((unsigned int)((p)[0]))

#define GLUE_GB16(p) (  ((unsigned int)((p)[0]) <<  8)                   \
                      | ((unsigned int)((p)[1])      ))

#define GLUE_GB32(p) (  ((unsigned int)((p)[0]) << 24)                   \
                      | ((unsigned int)((p)[1]) << 16)                   \
                      | ((unsigned int)((p)[2]) <<  8)                   \
                      | ((unsigned int)((p)[3])      ))


#define GLUE_SB08(p, v) ((p)[0] = ((unsigned char) (v)))

#define GLUE_SB16(p, v) ((p)[0] = ((unsigned char) ((v) >> 8)),               \
                         (p)[1] = ((unsigned char) ((v)     )))

#define GLUE_SB32(p, v) ((p)[0] = ((unsigned char) ((v) >> 24)),              \
                         (p)[1] = ((unsigned char) ((v) >> 16)),              \
                         (p)[2] = ((unsigned char) ((v) >>  8)),              \
                         (p)[3] = ((unsigned char) ((v)      )))


static int pkt_dpdk_algorithm_enqueue(rsp_context_t *ctx, struct rte_mbuf *in_mbuf, struct rte_cryptodev_sym_session *sess);
static int pkt_dpdk_algorithm(struct rte_mbuf *mbuf, SA_TBL *ipsec_sa, unsigned int alg, unsigned char * hash_data, unsigned int hash_len, unsigned int coreid);
static unsigned short ip_header_checksum_calc(unsigned char* ipv4Hdr);
static void ip_header_encape(unsigned char *pktcur, unsigned int curlen, SA_TBL *ipsec_sa, unsigned int srcip, unsigned int dstip);
static int  spkt_sync_mbuf(struct rte_mbuf *mbuf, unsigned char *pktcur, unsigned int curlen);

int zhijiang_sm4(struct rte_mbuf *mbuf, unsigned char *input, unsigned int in_len, unsigned int core_id, unsigned int enc);
int zhijiang_encry(struct rte_mbuf *mbuf, unsigned char *input, unsigned int in_len, unsigned int core_id);
int zhijiang_decry(struct rte_mbuf *mbuf, unsigned char *input, unsigned int in_len, unsigned int core_id);
int alg_test(uint32_t flag);





struct rte_mempool *ipsec_sess_mempool = NULL;
struct rte_mempool *ipsec_sess_priv_mempool = NULL;
struct rte_mempool *ipsec_op_pool = NULL;
int mc_dev_id = 0;
int mc_socket_id = 0;
unsigned int init_flag = 0;

unsigned int open_dbg=0;

unsigned int gIpsec4TunnelPktId = 0;


/* ������ */
pthread_mutex_t mutex ;


/* ���������� */

uint8_t test_iv[16] = {0xb1,0xb2,0xb3,0xb4,0xb1,0xb2,0xb3,0xb4,0xb1,0xb2,0xb3,0xb4,0xb1,0xb2,0xb3,0xb4};

uint8_t test_encrykey[16] = {0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4};

uint8_t test_hashkey[32] = {0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4,
							0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4,0xd1,0xd2,0xd3,0xd4};

/* ���������� */


#if ZHIJIANG_READ("��ӡ")

void DumpHex(void* data, size_t size) 
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		MSG_DISPLAY("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			MSG_DISPLAY(" ");
			if ((i+1) % 16 == 0) {
				MSG_DISPLAY("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					MSG_DISPLAY(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					MSG_DISPLAY("   ");
				}
				MSG_DISPLAY("|  %s \n", ascii);
			}
		}
	}
}

/*****************************************************************************
 * �������ƣ� softMemPrint
 * ���������� �����ڴ��ӡ
 * ���ʵı��� ��
 * �޸ĵı��� ��
 * ��������� ��
 * ��������� ��
 * �� �� ֵ�� ��
 * ����˵����
 *****************************************************************************/
void softMemPrint(unsigned char *pMem, unsigned int size)
{
    unsigned int i;
    unsigned int line = 0;
    if (NULL == pMem)
    {
        MSG_DISPLAY("pMem NULL error!\n");
        return;
    }
    if (0 == size)
    {
        return;
    }

	MSG_DISPLAY("BufLen = %d\n" ,size);
	
    MSG_DISPLAY("**********************************************************************\n");
    MSG_DISPLAY("[%p]: ", pMem);
    for (i = 0; i < size; i++)
    {
        MSG_DISPLAY("%02X ", *(pMem+i));
        if (0xF == (i & 0xF))
        {
            MSG_DISPLAY("\n");
            line ++;
            if (i < (size - 1))
            {
                MSG_DISPLAY("[%p]: ", (pMem+i+1));
            }
        }
    }
    if (0xF != ((i - 1) & 0xF))
    {
        MSG_DISPLAY("\n");
        line ++;
    }
    MSG_DISPLAY("MEM BYTE CNT[%u]            LINE[%u]\n", i, line);
    MSG_DISPLAY("**********************************************************************\n");
}


#endif


#if ZHIJIANG_READ("���ܿ���ʼ��")

int zhijiang_init_crypto_device(void)
{
	if(1 == init_flag)
	{	
		/* ����Ҫ���³�ʼ�� */
		return 0;
	}
	
	const char *name = ENCRY_CARD_DEVICE;
    int ret = 0;
    int j = 0;
    struct rte_cryptodev_config conf;
    struct rte_cryptodev_qp_conf qp_conf;
    int qp_num;
    struct rte_cryptodev_info dev_info;
	unsigned int size;

	
    //Get crypto device id 
    mc_dev_id = rte_cryptodev_get_dev_id(name);
    if(mc_dev_id < 0)
    {
        MSG_DISPLAY("Invalid crypto device name \n");
        return -1;
    }
    //get socket
    mc_socket_id = rte_cryptodev_socket_id(mc_dev_id);
    //get info
    rte_cryptodev_info_get(mc_dev_id, &dev_info);
    qp_num = dev_info.max_nb_queue_pairs;
    memset(&conf,0x00,sizeof(conf));
    conf.nb_queue_pairs = qp_num,
    conf.socket_id = mc_socket_id,
    ret = rte_cryptodev_configure(mc_dev_id, &conf);
    if(ret!=0)
    {
        MSG_DISPLAY("Config [%s] failed! \n",name);
        return -1;
    }
    
    memset(&qp_conf,0x00,sizeof(qp_conf));
	/* ���й������������أ������ʸ� */
    qp_conf.nb_descriptors = RSP_MAX_DEPTH/8;
    for (j = 0; j < qp_num; j++) 
    {//setup all QPs with MAX depth
        ret = rte_cryptodev_queue_pair_setup(mc_dev_id, j, &qp_conf, mc_socket_id);
        if (ret < 0)
        {
            MSG_DISPLAY("Failed to setup queue pair %u on " "cryptodev %u \n", j, mc_dev_id);
            return -1;
        }
    }

	/* ��������buf�ظ�ipsecҵ��ʹ�� ���֧��16K��sa��ͬʱ����*/
	MSG_DISPLAY("Initializing ipsec sess pool...\n ");
	ipsec_sess_mempool = rte_cryptodev_sym_session_pool_create("sess_pool", 16*1024, 0, 0, 1024, mc_socket_id);
	if (NULL == ipsec_sess_mempool) {
		MSG_DISPLAY("Initializing ipse sess pool fail!\n ");
		return -1;
	}

	MSG_DISPLAY("Initializing ipsec sess priv  pool...\n ");
	/* size��192 */
    size = rte_cryptodev_sym_get_private_session_size(mc_dev_id);
    ipsec_sess_priv_mempool = rte_mempool_create("sess_priv_pool", 16*1024, size, 0, 0, NULL, NULL, NULL, NULL, mc_socket_id, 0);
	if (NULL == ipsec_sess_priv_mempool) {
		MSG_DISPLAY("Initializing ipsec sess priv pool fail!\n ");
		return -1;
	}

	MSG_DISPLAY("Initializing ipsec op  pool...\n ");
    ipsec_op_pool = rte_crypto_op_pool_create("crypto_op_pool",RTE_CRYPTO_OP_TYPE_SYMMETRIC, RSP_MAX_DEPTH, 0, 64, mc_socket_id);
	if (NULL == ipsec_op_pool) {
		MSG_DISPLAY("Initializing ipsec op pool fail!\n ");
		return -1;
	}

	/* �����ʼ�� */
	init_nexthead();
	init_ethertype();
	init_sa();

	/* �����ú���Ӧ��ɾ�� */
	ret = add_sa(0, 36000, 0, 0, test_encrykey, test_iv, 0, test_hashkey, test_iv, 250);
	if(0 != ret)
	{
		MSG_DISPLAY("sa tbl add failed!!!");
		return -1;
	}
	
	ret = add_nexthead(0x0800, IPV4_PROTOCOL);
	if(0 != ret)
	{
		MSG_DISPLAY("nexthead tbl add failed!!!");
		return -1;
	}
	ret = add_nexthead(0x080a, GEO_PROTOCOL);
	if(0 != ret)
	{
		MSG_DISPLAY("nexthead tbl add failed!!!");
		return -1;
	}
	
	ret = add_ethertype(IPV4_PROTOCOL, 0x0800);
	if(0 != ret)
	{
		MSG_DISPLAY("ethertype tbl add failed!!!");
		return -1;
	}
	ret = add_ethertype(GEO_PROTOCOL, 0x080a);
	if(0 != ret)
	{
		MSG_DISPLAY("ethertype tbl add failed!!!");
		return -1;
	}
	/* �����ú���Ӧ��ɾ�� */
	
	init_flag = 1;
	
    return 0;
}


#endif


#if ZHIJIANG_READ("���ļӽ���")

static int pkt_dpdk_algorithm_enqueue(rsp_context_t *ctx, struct rte_mbuf *in_mbuf, struct rte_cryptodev_sym_session *sess)
{
	int count=0;
	int i;
	uint32_t ret = 0;
	int retVal = 0;

	uint8_t  *iv_data;
	uint16_t iv_offset;
	uint16_t iv_length;

	struct rte_crypto_op *enqueued_op;
	struct rte_crypto_op *dequeued_op;
	struct rte_crypto_sym_op *sym_op;
	uint8_t *iv_ptr = NULL;
	

	/* ����once��ops����ÿ�Զ�Ӧ�ļӽ�����Ϣ */
	//just alloc enq op from pool
	retVal = rte_crypto_op_bulk_alloc(ipsec_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, &enqueued_op, 1);
	if(!retVal)
	{
		ret = ret|0x10;
		return ret;
	}
	
	//setup ops
	enqueued_op->reserved[0] = 0;
	enqueued_op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
	retVal = rte_crypto_op_attach_sym_session(enqueued_op, sess);
	if(-1 == retVal)
	{
		ret = ret|0x20;
		return ret;
	}

	/* sm4 */
    iv_length  = IV_LEN;
    iv_data    = ctx->iv;
    iv_offset  = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op);
	
	//set IV
    iv_ptr = rte_crypto_op_ctod_offset(enqueued_op, uint8_t *,iv_offset);
    memcpy(iv_ptr, iv_data, iv_length);
	
	sym_op = enqueued_op->sym;
    sym_op->m_src = in_mbuf;
    sym_op->m_dst = NULL;//dst buffer is null,so the cipher will instead of src buffer
    
    sym_op->cipher.data.length = ctx->c_size;//cipher length
    sym_op->cipher.data.offset = ctx->c_offset;//cipher data offset skip esp iv
    
    sym_op->auth.data.length = ctx->a_size;//auth length(contain esp+iv+cipher)
    sym_op->auth.data.offset = ctx->a_offset;
    /* hmac�Ľ�����ڱ��ĵ�ĩβ */
    sym_op->auth.digest.data      = (rte_pktmbuf_mtod(in_mbuf, uint8_t *)+ctx->a_offset+ctx->a_size);
    sym_op->auth.digest.phys_addr = (rte_pktmbuf_iova(in_mbuf)+ctx->a_offset+ctx->a_size);

	if (open_dbg) {
		MSG_DISPLAY("sym_op->cipher.data.length:%d\n", sym_op->cipher.data.length);
		MSG_DISPLAY("sym_op->cipher.data.offset:%d\n", sym_op->cipher.data.offset);
		MSG_DISPLAY("sym_op->auth.data.length:%d\n", sym_op->auth.data.length);
		MSG_DISPLAY("sym_op->auth.data.offset:%d\n", sym_op->auth.data.offset);
		MSG_DISPLAY("sm3 ctx->a_size:%d\n", ctx->a_size);
		MSG_DISPLAY("sm3 offset addrs:%p\n", (rte_pktmbuf_mtod(in_mbuf, uint8_t *)+ctx->a_offset));
		softMemPrint((rte_pktmbuf_mtod(in_mbuf, uint8_t *)+ctx->a_offset), ctx->a_size);
		MSG_DISPLAY("sm4 ctx->c_size:%d\n", ctx->c_size);
		MSG_DISPLAY("sm4 offset addrs:%p\n", (rte_pktmbuf_mtod(in_mbuf, uint8_t *)+ctx->c_offset));
		softMemPrint((rte_pktmbuf_mtod(in_mbuf, uint8_t *)+ctx->c_offset), ctx->c_size);
		MSG_DISPLAY("iv_data:\n");
		softMemPrint(iv_data,IV_LEN);
	}

	count = rte_cryptodev_enqueue_burst(ctx->dev_id, ctx->qp_id, &enqueued_op, 1);
	for(i=(count);i<1;i++)
	{
		/* ���ʧ���ͷ� */
		rte_crypto_op_free(enqueued_op);
		ret = ret|0x80;
		return ret;
	}

	/* ���� */
	ret = 0;
    do{
	    ret = rte_cryptodev_dequeue_burst(ctx->dev_id, ctx->qp_id, &dequeued_op, 1);
	    if(ret!=0)
	    {
	        MSG_DISPLAY("Dequeue op %d \n",ret);
	        struct rte_mbuf *mbuf = dequeued_op->sym->m_src;
			MSG_DISPLAY("dequeue:out_mbuf0x%x\n", mbuf);
			MSG_DISPLAY("dequeued_op->sym->session:0x%x\n", dequeued_op->sym->session);
	    }
    }while(!ret);

	
	rte_crypto_op_free(enqueued_op);
	
	return 0;
}


static int pkt_dpdk_algorithm(struct rte_mbuf *mbuf, SA_TBL *ipsec_sa, unsigned int alg, unsigned char * hash_data, unsigned int hash_len, unsigned int coreid)
{
	rsp_context_t ctx;
	unsigned int ret = 0;
	unsigned char *ptr = NULL;
	unsigned char *iv = NULL;
    unsigned short iv_offset;
	struct rte_cryptodev_sym_session *sess = NULL;
	struct rte_crypto_sym_xform xform;
	struct rte_crypto_sym_xform xform1;


	if(NULL == mbuf)
	{
		ret = ret|1;
		return ret;
	}

	ptr = rte_pktmbuf_mtod(mbuf, unsigned char *);

	if((unsigned long long)ptr % 2)
	{
		ret = ret|2;
		/* ����/��֤���ݵ���ʼ��ַ������2�ֽڵ������� */
		return ret;
	}

	iv = (hash_data + ESP_HEADER_LEN);
	ctx.qp_id		 = coreid;
	ctx.dev_id		 = mc_dev_id;
	ctx.socket_id	 = mc_socket_id;
	ctx.iv			 = iv;
	
	/* hash��ƫ�ƺͳ��� */
	ctx.a_offset = hash_data - ptr;
	ctx.a_size = hash_len;
	
	/* ���ܵ�ƫ�ƺͳ���,д����1��espͷ����һ��iv */
	ctx.c_offset = ctx.a_offset + ESP_HEADER_LEN + IV_LEN;
	ctx.c_size = hash_len - (ESP_HEADER_LEN + IV_LEN);

	if (open_dbg) {
		MSG_DISPLAY("ctx.a_size:%d ctx.a_offset:%d\n", ctx.a_size, ctx.a_offset);
		softMemPrint(ptr + ctx.a_offset, ctx.a_size);
		MSG_DISPLAY("ctx.c_size:%d ctx.c_offset:%d\n", ctx.c_size, ctx.c_offset);
		softMemPrint(ptr + ctx.c_offset , ctx.c_size);
	}

	//create session & init
    sess = rte_cryptodev_sym_session_create(ipsec_sess_mempool);
    if(sess == NULL)
    {
		MSG_DISPLAY("Session create failed !\n");
		return 0;
    }
	
	if(SM4_SM3 == alg)
	{
		/* ������֤ */
        iv_offset  = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op);
        //SM4 param config
        xform.type             = RTE_CRYPTO_SYM_XFORM_CIPHER;
        xform.next             = &xform1;
        xform.cipher.algo      = 0xFF;
        xform.cipher.op        = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
        xform.cipher.iv.offset = iv_offset;
        xform.cipher.iv.length = IV_LEN;
        xform.cipher.key.data  = ipsec_sa->cipher_key;
        xform.cipher.key.length= CIPHER_KEY_LEN;
        
        //SM3 config
        xform1.type             = RTE_CRYPTO_SYM_XFORM_AUTH;
        xform1.next             = NULL;
        xform1.auth.algo        = 0xFD;
        xform1.auth.key.data    = ipsec_sa->hash_key;
        xform1.auth.key.length  = HASH_KEY_LEN;
        xform1.auth.digest_length = HASH_RESULT_LEN;

		if (open_dbg) {
			MSG_DISPLAY("xform.cipher.key.data:\n", xform.cipher.key.data);
			softMemPrint(xform.cipher.key.data, CIPHER_KEY_LEN);
			MSG_DISPLAY("xform.auth.key.data:\n", xform1.auth.key.data);
			softMemPrint(xform1.auth.key.data, HASH_KEY_LEN);
		}


	    /* �㷨�Ͳ����·����ײ��豸 */
	    ret=rte_cryptodev_sym_session_init(ctx.dev_id, sess, &xform, ipsec_sess_priv_mempool);
	    if(ret!=0)
	    {
	        MSG_DISPLAY("sym_sess init failed ret=%d !\n");
			ret = ret|0x40;
			rte_cryptodev_sym_session_clear(ctx.dev_id, sess);
    		rte_cryptodev_sym_session_free(sess);
			return ret;
	    }
	}
	else
	{
		/* ���ܽ���֤ */
        iv_offset  = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op);
		//SM4 param config
		xform.type			   = RTE_CRYPTO_SYM_XFORM_CIPHER;
		xform.next			   = NULL;
		xform.cipher.algo	   = 0xFF;
		xform.cipher.op 	   = RTE_CRYPTO_CIPHER_OP_DECRYPT;
		xform.cipher.iv.offset = (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op));
		xform.cipher.iv.length = IV_LEN;
		xform.cipher.key.data  = ipsec_sa->cipher_key;
		xform.cipher.key.length= CIPHER_KEY_LEN;

		//SM3 config
		xform1.type             = RTE_CRYPTO_SYM_XFORM_AUTH;
        xform1.next             = &xform;
        xform1.auth.algo        = 0xFD;
        xform1.auth.key.data    = ipsec_sa->hash_key;
        xform1.auth.key.length  = HASH_KEY_LEN;
        xform1.auth.digest_length = HASH_RESULT_LEN;

		if (open_dbg) {
			MSG_DISPLAY("xform.cipher.key.data:\n", xform.cipher.key.data);
			softMemPrint(xform.cipher.key.data, CIPHER_KEY_LEN);
			MSG_DISPLAY("xform.auth.key.data:\n", xform1.auth.key.data);
			softMemPrint(xform1.auth.key.data, HASH_KEY_LEN);
		}

	    /* �㷨�Ͳ����·����ײ��豸 */
	    ret=rte_cryptodev_sym_session_init(ctx.dev_id, sess, &xform, ipsec_sess_priv_mempool);
	    if(ret!=0)
	    {
	        MSG_DISPLAY("sym_sess init failed ret=%d !\n");
	        ret = ret|0x80;
			rte_cryptodev_sym_session_clear(ctx.dev_id, sess);
    		rte_cryptodev_sym_session_free(sess);
			return ret;
	    }
		
	}

	ret = pkt_dpdk_algorithm_enqueue(&ctx, mbuf, sess);
	if(ret!=0)
    {
        MSG_DISPLAY("sym_sess init failed ret=%d !\n");
        ret = ret|0x100;
		rte_cryptodev_sym_session_clear(ctx.dev_id, sess);
    	rte_cryptodev_sym_session_free(sess);
		return ret;
    }

	/* �ͷ������sess */
	rte_cryptodev_sym_session_clear(ctx.dev_id, sess);
    rte_cryptodev_sym_session_free(sess);
	return 0;
}

#endif


#if ZHIJIANG_READ("���ķ�װ")

static void ip_header_encape(unsigned char *pktcur, unsigned int curlen, SA_TBL *ipsec_sa, unsigned int srcip, unsigned int dstip)
{
	unsigned char nextheader = ESP_PROTOCOL;
	unsigned char *pNewIpHeader;
	unsigned short totalLen;
	unsigned short identification;
	unsigned short checksum;

	pNewIpHeader = pktcur;
	
	GLUE_SB08(pNewIpHeader, 0x45);
	GLUE_SB08(pNewIpHeader+1, 0);
	
	totalLen = (ipsec_sa->hash_alg) ? (curlen+AUTHEN_DATA_LENGTH) : (curlen);
	GLUE_SB16(pNewIpHeader+2, totalLen);

	pthread_mutex_lock(&mutex);
	identification = ++gIpsec4TunnelPktId;
	pthread_mutex_unlock(&mutex);
	
	GLUE_SB16(pNewIpHeader+4, identification);
	GLUE_SB16(pNewIpHeader+6, 0);
	GLUE_SB08(pNewIpHeader+8, MAX_TTL);
	GLUE_SB08(pNewIpHeader+9, nextheader);
	GLUE_SB16(pNewIpHeader+10, 0);
	GLUE_SB32(pNewIpHeader+12, srcip);
	GLUE_SB32(pNewIpHeader+16, dstip);
	
	checksum = ip_header_checksum_calc(pktcur);
	GLUE_SB16(pNewIpHeader+10, checksum);

	if(open_dbg)
	{
		MSG_DISPLAY("pkt after encape:\n");
		softMemPrint(pktcur, curlen);
	}
}

/*****************************************************************************
 * �������ƣ� softfpIpv4HdrChecksumCalc
 * ���������� ����IPͷ��checksum
 * ���ʵı��� ��
 * �޸ĵı��� ��
 * ��������� ipv4Hdr ipͷָ��
 * ��������� �ޡ�
 * �� �� ֵ�� checksum
 * ����˵���� ��      
 * �޸�����         �汾��           �޸���            �޸�����
 * ---------------------------------------------------------------------------
 * 2011-07-11      V1.00.10          yanwen              �½�
 *****************************************************************************/
static unsigned short ip_header_checksum_calc(unsigned char* ipv4Hdr)
{

    unsigned int checksum = 0;
    unsigned char off = 0;
	unsigned int ipHdrInfo0 = GLUE_GB32(ipv4Hdr);
	unsigned char ipheaderlen = (ipHdrInfo0 >> 22) & 0x3C;
	
    while (off < ipheaderlen)
    {
        if (10 != off)
        {
            checksum += GLUE_GB16(ipv4Hdr+off);
        }
        off += 2;
    }
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);
	
    return (unsigned short)(~checksum);
	
}

static int  spkt_sync_mbuf(struct rte_mbuf *mbuf, unsigned char *pktcur, unsigned int curlen)
{

	int data_off = pktcur - (unsigned char *)mbuf->buf_addr;
	if(0 > data_off)
	{
		return UNSUCESS;
	}
	mbuf->data_off = data_off;
	mbuf->pkt_len = curlen;
	unsigned short rest = mbuf->buf_len - mbuf->data_off;
	if (unlikely(mbuf->pkt_len > rest)) {
		mbuf->data_len = rest;
	} else {
	    mbuf->data_len = mbuf->pkt_len;
	}
	
	return SUCESS;
	
}


/*****************************************************************************
 * �������ƣ� IPSec
 * ���������� esp������֤
 * ���ʵı��� ��
 * �޸ĵı��� ��
 * ��������� 
 			  srcip:�µ�ipͷ��Դip
 			  dstip:�µ�ipͷ��Ŀ��ip
 			  coreid:��ǰ�̺߳�

 			  Ŀ��mac+Դmac+ethtype+ģ̬�ײ�+�غ�
               
 * ��������� Ŀ��mac+Դmac+ethtype+IPͷ+ESPͷ+ģ̬�ײ�+�غ�+espβ��+hash���
 												|----------enc-----|
 										 |-------------hash--------|
 * �� �� ֵ��  
 *****************************************************************************/
unsigned int IPSec(struct rte_mbuf *in_mbuf, unsigned int spi, unsigned int srcip, unsigned int dstip, unsigned int coreid)
{
	unsigned char meta_head[MAC_HEAD_LEN];
	unsigned char *tmpcur = NULL;
	unsigned char *current = NULL;
	unsigned char *hash_data = NULL;
	unsigned int current_len = 0;
	unsigned int hash_len = 0;
	SA_TBL *ipsec_sa = NULL;
	unsigned char espTailLen = 0;
	unsigned short eth_type = 0;
	unsigned char next_head = 0;
	unsigned int seq_no = 0;
	unsigned int ret = 0;
	int retVal = SUCESS;

	if(open_dbg){
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
	    rte_pktmbuf_dump(stdout, in_mbuf, rte_pktmbuf_pkt_len(in_mbuf));
	}


	if(NULL == in_mbuf)
	{
		ret |= 1;
		return ret;
	}

	/* ����sa�� */
	retVal = query_sa(spi, &ipsec_sa);
	if(SUCESS != retVal)
	{
		ret |= 2;
		return ret;
	}


	/* ��ȡ���ݰ�����ͷ��ָ�� */
	current = rte_pktmbuf_mtod(in_mbuf, uint8_t *);
	current_len = rte_pktmbuf_pkt_len(in_mbuf);


	/* ��ȡ��̫����,����nexthead */
	tmpcur = current + MAC_HEAD_LEN - 2;
	eth_type = GLUE_GB16(tmpcur);
	
	//eth_type = *(unsigned short *)(current + MAC_HEAD_LEN - 2);

	if(open_dbg)
	{
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
		MSG_DISPLAY("spi:0x%x\n", spi);
		MSG_DISPLAY("coreid:0x%x\n", coreid);
		MSG_DISPLAY("current_len:%d\n", current_len);
		MSG_DISPLAY("eth_type:0x%x\n", eth_type);
		MSG_DISPLAY("pkt before encape:\n");
		softMemPrint(current, current_len);
	}
	
	retVal = query_nexthead(eth_type, &next_head);
	if(SUCESS != retVal)
	{
		ret |= 0x10;
		return ret;
	}


	/* �������ͷ/β��Ϣ */
	memcpy((unsigned char*)meta_head, current, MAC_HEAD_LEN - 2);
	meta_head[12] = 0x08;
	meta_head[13] = 0x00;


	/* ָ��ģ̬�ײ� */
	current += MAC_HEAD_LEN;
	current_len -= MAC_HEAD_LEN;

	
	/* ��װespβ�� */
	tmpcur = current + current_len;
	espTailLen = (((~((current_len + ESP_TAIL_LEN) & 0xf)) + 1) & 0xf);

	if(open_dbg)
	{
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
		MSG_DISPLAY("espTailLen:%d\n", espTailLen);
		MSG_DISPLAY("next_head:%d\n", next_head);
	}
	
	IPSEC_ENCAP_ESP_TAIL(tmpcur, espTailLen);
	current_len += espTailLen;
	
	
	/*��װespβ�����ֶκ�nextheader�ֶ�*/
	tmpcur = current+current_len;
	*tmpcur = espTailLen;
	tmpcur++;
	*tmpcur = next_head;
	current_len += ESP_TAIL_LEN;
	

	/* ��װiv�ֶ� */
	tmpcur = current - IV_LEN;
	IPSEC_ENCAP_ESP_IV(tmpcur, IV_LEN);
	
	current -= IV_LEN;
	current_len += IV_LEN;

	/* ��װespͷ */
	tmpcur = current - ESP_HEADER_LEN;
	GLUE_SB32(tmpcur, ipsec_sa->spi);
	tmpcur += 4;
	 
	/* SA�������кż�1 */
	//ipsec_sa->seq_no++;
	GLUE_SB32(tmpcur, seq_no);
	current -= ESP_HEADER_LEN;
	current_len += ESP_HEADER_LEN;

	if(open_dbg)
	{
		MSG_DISPLAY("iv_len:%d\n", IV_LEN);
		MSG_DISPLAY("pkt after encape esp head/tail:\n");
		softMemPrint(current, current_len);
	}
	
	/* hash�ķ�Χ����espͷ����espβ�� */
	hash_data = current;
	hash_len = current_len;

	/* ��װ���ipͷ */
	current -= NORMAL_IP_HEADER_LEN;
	current_len += NORMAL_IP_HEADER_LEN;
	ip_header_encape(current, current_len, ipsec_sa, srcip, dstip);


	/* 12�ֽ���֤�ֶη��ڱ�������� */
	current_len += AUTHEN_DATA_LENGTH;

	
	/* ����mbuf����Ϣ */
	retVal = spkt_sync_mbuf(in_mbuf, current, current_len);
	if(SUCESS != retVal)
	{
		ret |= 4;
		return ret;
	}

	/* ������֤ */
	pkt_dpdk_algorithm(in_mbuf, ipsec_sa, SM4_SM3, hash_data, hash_len, coreid);

	if(open_dbg)
	{
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
		MSG_DISPLAY("pkt after encry:");
		MSG_DISPLAY("current_len:%d\n", current_len);
		softMemPrint(current, current_len);
	}

	
	/* �ָ�����ͷ��Ϣ */
	current -= MAC_HEAD_LEN;
	memcpy(current, (unsigned char*)meta_head, MAC_HEAD_LEN);
	current_len += MAC_HEAD_LEN;

	if(open_dbg)
	{
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
		MSG_DISPLAY("pkt after mac encape:");
		MSG_DISPLAY("current_len+4:%d\n", current_len+4);
		softMemPrint(current, current_len+4);
	}
	
	/* ����mbuf����Ϣ */
	retVal = spkt_sync_mbuf(in_mbuf, current, current_len);
	if(SUCESS != retVal)
	{
		ret |= 8;
		return ret;
	}

	if(open_dbg){
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
	    rte_pktmbuf_dump(stdout, in_mbuf, rte_pktmbuf_pkt_len(in_mbuf));
	}
	return 0;
	
}


/*****************************************************************************
 * �������ƣ� unIPSec
 * ���������� esp����֮ǰ�ķ�װ����
 * ���ʵı��� ��
 * �޸ĵı��� ��
 * ��������� Ŀ��mac+Դmac+ethtype+IPͷ+ESPͷ+ģ̬�ײ�+�غ�+espβ��+hash���
 												|----------enc-----|
 										 |-------------hash--------|
               
 * ��������� Ŀ��mac+Դmac+ethtype+ģ̬�ײ�+�غ�
 * �� �� ֵ��  
 *****************************************************************************/
unsigned int unIPSec(struct rte_mbuf *in_mbuf, unsigned int coreid)
{
	unsigned char meta_head[MAC_HEAD_LEN];
	unsigned char result[AUTHEN_DATA_LENGTH];
	unsigned char *tmpcur = NULL;
	unsigned char *current = NULL;
	unsigned char *hash_data = NULL;
	unsigned int current_len = 0;
	unsigned int hash_len = 0;
	SA_TBL *ipsec_sa = NULL;
	unsigned int spi = 0;
	unsigned int seqnum = 0;
	unsigned int esp_tail_len = 0;
	unsigned char next_head = 0;
	unsigned short eth_type = 0;
	unsigned int ret = 0;
	int retVal = SUCESS;


	if((NULL == in_mbuf))
	{
		ret |= 1;
		return ret;		
	}


	/* ��ȡ���ݰ�����ͷ��ָ�� */
	current = rte_pktmbuf_mtod(in_mbuf, uint8_t *);
	current_len = rte_pktmbuf_pkt_len(in_mbuf);


	if(open_dbg)
	{
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
		MSG_DISPLAY("pkt before encape:");
		softMemPrint(current, current_len);
	}
	
	
	/* �������ͷ/β��Ϣ */
	memcpy((unsigned char*)meta_head, current, MAC_HEAD_LEN);


	/* ָ��ģ̬�ײ� */
	current += MAC_HEAD_LEN;
	current_len -= MAC_HEAD_LEN;
	

	/* ����esp��֤��� */
	memcpy((unsigned char*)result, (current+current_len-AUTHEN_DATA_LENGTH), AUTHEN_DATA_LENGTH);

	
	/* ��ȡSPI ��seqnum */
	spi = GLUE_GB32(current + NORMAL_IP_HEADER_LEN);
	seqnum = GLUE_GB32(current + NORMAL_IP_HEADER_LEN + AH_SEQUENCE_OFFSET);

	if (open_dbg) {
		MSG_DISPLAY("spi:%d\n", spi);
		MSG_DISPLAY("seqnum:%d\n", seqnum);
	}

	/* ����sa�� */
	retVal = query_sa(spi, &ipsec_sa);
	if(SUCESS != retVal)
	{
		ret |= 2;
		return ret;
	}

	/* ����mbuf����Ϣ */
	retVal = spkt_sync_mbuf(in_mbuf, current, current_len);
	if(SUCESS != retVal)
	{
		ret |= 4;
		return ret;
	}

	hash_data = current + NORMAL_IP_HEADER_LEN;
	hash_len = current_len - AUTHEN_DATA_LENGTH - NORMAL_IP_HEADER_LEN;

	/* ���ܽ���֤ */
	pkt_dpdk_algorithm(in_mbuf, ipsec_sa, SM3_SM4, hash_data, hash_len, coreid);
	
	if (open_dbg) {
		MSG_DISPLAY("hash result1:\n");
		softMemPrint(result, AUTHEN_DATA_LENGTH);
		MSG_DISPLAY("hash result2:\n");
		softMemPrint((hash_data + hash_len), AUTHEN_DATA_LENGTH);
	}

	/* �ȽϽ���֤��� */
	if(memcmp(result, (hash_data + hash_len), AUTHEN_DATA_LENGTH))
	{
		ret |= 8;
		return ret;
	}

	current_len -= AUTHEN_DATA_LENGTH;

	/* ��ȡespβ��nextheader�ֶ� */
	tmpcur = (current + current_len - ESP_TAIL_LEN + 1);
	next_head = GLUE_GB08(tmpcur);
	//next_head = *(current + current_len - ESP_TAIL_LEN + 1);

	/* ���װ,����espβ��,���ipͷ��espͷ */
	tmpcur = (current + current_len - ESP_TAIL_LEN);
	esp_tail_len = GLUE_GB08(tmpcur);
	//esp_tail_len = *(current + current_len - ESP_TAIL_LEN);
	if(esp_tail_len > 17)
	{
		ret |= 0x10;
		return ret;
	}

	current_len -= (esp_tail_len + ESP_TAIL_LEN);
	current += (NORMAL_IP_HEADER_LEN + ESP_HEADER_LEN + IV_LEN);
	current_len -= (NORMAL_IP_HEADER_LEN + ESP_HEADER_LEN + IV_LEN);

	if(open_dbg)
	{
		MSG_DISPLAY("next_head:%d\n", next_head);
		MSG_DISPLAY("esp_tail_len:%d\n", esp_tail_len);
		MSG_DISPLAY("pkt after decape:");
		softMemPrint(current, current_len);
	}

	/* ����eth_type */
	retVal = query_ethertype(next_head, &eth_type);
	if(SUCESS != retVal)
	{
		ret |= 0x20;
		return ret;
	}
	
	/* ��װ���� */
	/* 封装二层 */
	current -= MAC_HEAD_LEN;
	current_len += MAC_HEAD_LEN;
	memcpy(current, meta_head, (MAC_HEAD_LEN - MAC_TYPE_LEN));
	if(open_dbg)
	{
		MSG_DISPLAY("eth_type:0x%x\n", eth_type);
		MSG_DISPLAY("pkt after decape:");
		softMemPrint(current, current_len);
	}
	
	//tmpcur = current + MAC_HEAD_LEN - MAC_TYPE_LEN;
	tmpcur = current + 12;
	GLUE_SB16(tmpcur, eth_type);

	if(open_dbg)
	{
		MSG_DISPLAY("eth_type:0x%x\n", eth_type);
		MSG_DISPLAY("pkt after decape:");
		softMemPrint(current, current_len);
	}

	/* ����mbuf����Ϣ */
	retVal = spkt_sync_mbuf(in_mbuf, current, current_len);
	if(SUCESS != retVal)
	{
		ret |= 0x40;
		return ret;		
	}
	
	return 0;
}


#endif

#if ZHIJIANG_READ("���Ժ���")
uint8_t test_input[64] = {0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,
					   0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,
					   0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,
					   0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4};


uint8_t test_input3[128] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
					   0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
					   0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,
					   0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,
					   0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,
					   0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,0xa1,0xa2,0xa3,0xa4,
					   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};


int test_cipher_running(rsp_context_t *ctx, struct rte_mbuf *in_mbuf, struct rte_mbuf *out_mbuf, uint32_t flag)
{
    int ret = 0;
    int i;

    uint8_t  *iv_data;
    uint16_t iv_offset;
    uint16_t iv_length;

    
    struct rte_cryptodev_sym_session *sess[1];
    struct rte_crypto_sym_xform xform;
	struct rte_crypto_sym_xform xform1;

	struct rte_crypto_op *enqueued_op;
    struct rte_crypto_op *dequeued_op;
    struct rte_crypto_sym_op *sym_op;

    ret = 0;

	/* ����once��ops����ÿ�Զ�Ӧ�ļӽ�����Ϣ */
    //just alloc enq op from pool
    rte_crypto_op_bulk_alloc(ipsec_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, &enqueued_op, 1);
	MSG_DISPLAY("crypto_op_bulk_alloc ok!!!\n");
	
    //setup ops
    enqueued_op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

	switch(ctx->op)
    {
    	case SM4_CBC:
			{
				iv_length  = 16;
	            iv_data    = ctx->iv;
	            iv_offset  = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op);
	            xform.type             = RTE_CRYPTO_SYM_XFORM_CIPHER;
	            xform.next             = NULL;
	            xform.cipher.algo      = 0xFF;
	            xform.cipher.op        = flag;
	            xform.cipher.iv.offset = iv_offset;
	            xform.cipher.iv.length = iv_length;
	            xform.cipher.key.data  = test_encrykey;
	            xform.cipher.key.length= CIPHER_KEY_LEN;

				//create session & init
			    sess[0] = rte_cryptodev_sym_session_create(ipsec_sess_mempool);
			    if(sess[0] == NULL)
			    {
					MSG_DISPLAY("Session create failed !\n");
					return 0;
			    }

			    /* �㷨�Ͳ����·����ײ��豸 */
			    ret=rte_cryptodev_sym_session_init(ctx->dev_id, sess[0], &xform, ipsec_sess_priv_mempool);
			    if(ret!=0)
			    {
			        MSG_DISPLAY("sym_sess init failed ret=%d !\n");
			        return 0;
			    }

				rte_crypto_op_attach_sym_session(enqueued_op, sess[0]);
				if(-1 == ret)
				{
					ret = ret|0x10;
					return ret;
				}

				//set IV
				uint8_t *iv_ptr = rte_crypto_op_ctod_offset(enqueued_op, uint8_t *,iv_offset);
				memcpy(iv_ptr, iv_data, iv_length);

				sym_op = enqueued_op->sym;
				
			    sym_op->m_src = in_mbuf;
			    sym_op->m_dst = NULL;
		        sym_op->cipher.data.length = ctx->c_size;
		        sym_op->cipher.data.offset = ctx->c_offset;

				MSG_DISPLAY("c_key_data:\n");
				softMemPrint(xform.cipher.key.data+ctx->c_offset,16);
				MSG_DISPLAY("iv_data:\n");
				softMemPrint(iv_data,16);
				
    		}
			break;
	    case SM4_SM3:
			{
	            iv_length  = 16;
	            iv_data    = ctx->iv;
	            iv_offset  = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op);
	            //SM4 param config
	            xform.type             = RTE_CRYPTO_SYM_XFORM_CIPHER;
	            xform.next             = &xform1;
	            xform.cipher.algo      = 0xFF;
	            xform.cipher.op        = flag;
	            xform.cipher.iv.offset = iv_offset;
	            xform.cipher.iv.length = iv_length;
	            xform.cipher.key.data  = test_encrykey;
	            xform.cipher.key.length= CIPHER_KEY_LEN;
	            
	            //SM3 config
	            xform1.type             = RTE_CRYPTO_SYM_XFORM_AUTH;
	            xform1.next             = NULL;
	            xform1.auth.algo        = 0xFD;
	            xform1.auth.key.data    = test_hashkey;
	            xform1.auth.key.length  = HASH_KEY_LEN;
	            xform1.auth.digest_length = HASH_RESULT_LEN;

				//create session & init
			    sess[0] = rte_cryptodev_sym_session_create(ipsec_sess_mempool);
			    if(sess[0] == NULL)
			    {
					MSG_DISPLAY("Session create failed !\n");
					ret = ret|0x20;
					return ret;
			    }

			    /* �㷨�Ͳ����·����ײ��豸 */
			    ret=rte_cryptodev_sym_session_init(ctx->dev_id, sess[0], &xform, ipsec_sess_priv_mempool);
			    if(ret!=0)
			    {
			        MSG_DISPLAY("sym_sess init failed ret=%d !\n");
					ret = ret|0x40;
					return ret;
			    }

				rte_crypto_op_attach_sym_session(enqueued_op, sess[0]);
				if(-1 == ret)
				{
					ret = ret|0x10;
					return ret;
				}


				//set IV
				uint8_t *iv_ptr = rte_crypto_op_ctod_offset(enqueued_op, uint8_t *,iv_offset);
				memcpy(iv_ptr, iv_data, iv_length);

				sym_op = enqueued_op->sym;
				
                sym_op->m_src = in_mbuf;
                sym_op->m_dst = out_mbuf;
                
                sym_op->cipher.data.length = ctx->c_size;//cipher length
                sym_op->cipher.data.offset = ctx->c_offset;//skip esp
                
                sym_op->auth.data.length = ctx->a_size;//auth length(contain esp+cipher)
                sym_op->auth.data.offset = ctx->a_offset;
                
                sym_op->auth.digest.data      = rte_pktmbuf_mtod(in_mbuf, uint8_t *)+ctx->a_offset+ctx->a_size;
                sym_op->auth.digest.phys_addr = rte_pktmbuf_iova(in_mbuf)+ctx->a_offset+ctx->a_size;

				MSG_DISPLAY("iv_data:\n");
				softMemPrint(iv_data,IV_LEN);
				MSG_DISPLAY("c_key_data:\n");
				softMemPrint(xform.cipher.key.data,CIPHER_KEY_LEN);
				MSG_DISPLAY("a_key_data:\n");
				softMemPrint(xform1.auth.key.data,HASH_RESULT_LEN);
			}
			break;
		case SM3_SM4:
			{
				iv_length  = IV_LEN;
	            iv_data    = ctx->iv;
	            iv_offset  = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op);
				
				xform.type			   = RTE_CRYPTO_SYM_XFORM_CIPHER;
				xform.next			   = NULL;
				xform.cipher.algo	   = 0xFF;
				xform.cipher.op 	   = RTE_CRYPTO_CIPHER_OP_DECRYPT;
				xform.cipher.iv.offset = (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op));
				xform.cipher.iv.length = IV_LEN;
				xform.cipher.key.data  = test_encrykey;
				xform.cipher.key.length= CIPHER_KEY_LEN;

				xform1.type             = RTE_CRYPTO_SYM_XFORM_AUTH;
	            xform1.next             = &xform;
	            xform1.auth.algo        = 0xFD;
	            xform1.auth.key.data    = test_hashkey;
	            xform1.auth.key.length  = HASH_KEY_LEN;
	            xform1.auth.digest_length = HASH_RESULT_LEN;	

				//create session & init
			    sess[0] = rte_cryptodev_sym_session_create(ipsec_sess_mempool);
			    if(sess[0] == NULL)
			    {
					MSG_DISPLAY("Session create failed !\n");
					ret = ret|0x80;
					return ret;
			    }

			    /* �㷨�Ͳ����·����ײ��豸 */
			    ret=rte_cryptodev_sym_session_init(ctx->dev_id, sess[0], &xform, ipsec_sess_priv_mempool);
			    if(ret!=0)
			    {
			        MSG_DISPLAY("sym_sess init failed ret=%d !\n");
			        ret = ret|0x100;
					return ret;
			    }

				rte_crypto_op_attach_sym_session(enqueued_op, sess[0]);
				if(-1 == ret)
				{
					ret = ret|0x10;
					return ret;
				}

				//set IV
				uint8_t *iv_ptr = rte_crypto_op_ctod_offset(enqueued_op, uint8_t *,iv_offset);
				memcpy(iv_ptr, iv_data, iv_length);

				sym_op = enqueued_op->sym;
				
                sym_op->m_src = in_mbuf;
                sym_op->m_dst = out_mbuf;
                
                sym_op->cipher.data.length = ctx->c_size;//cipher length
                sym_op->cipher.data.offset = ctx->c_offset;//skip esp
                
                sym_op->auth.data.length = ctx->a_size;//auth length(contain esp+cipher)
                sym_op->auth.data.offset = ctx->a_offset;
                
                sym_op->auth.digest.data      = rte_pktmbuf_mtod(in_mbuf, uint8_t *)+ctx->a_offset+ctx->a_size;
                sym_op->auth.digest.phys_addr = rte_pktmbuf_iova(in_mbuf)+ctx->a_offset+ctx->a_size;
				
				MSG_DISPLAY("iv_data:\n");
				softMemPrint(iv_data,IV_LEN);
				MSG_DISPLAY("c_key_data:\n");
				softMemPrint(xform.cipher.key.data,CIPHER_KEY_LEN);
				MSG_DISPLAY("a_key_data:\n");
				softMemPrint(xform1.auth.key.data,HASH_KEY_LEN);
			}
			break;
		default:
			break;
	}


	MSG_DISPLAY("enqueue:in_mbuf:0x%x\n", in_mbuf);
	MSG_DISPLAY("sess[0]0x%x\n", sess[0]);
	
    //enq ops
    ret = rte_cryptodev_enqueue_burst(ctx->dev_id, ctx->qp_id, &enqueued_op, 1);
    for(i=(ret);i<1;i++)
    {
    	MSG_DISPLAY("Enqueue error !!!\n");
    	/* ���ʧ���ͷ� */
        //rte_pktmbuf_free(enqueued_op->sym->m_src);
        //free enq failed ops
        rte_crypto_op_free(enqueued_op);
		rte_cryptodev_sym_session_clear(ctx->dev_id, sess[0]);
    	rte_cryptodev_sym_session_free(sess[0]);

		ret = ret|0x200;
		return ret;

    }

	ret = 0;
    //deq ops
    do{
	    ret = rte_cryptodev_dequeue_burst(ctx->dev_id, ctx->qp_id, &dequeued_op, 1);
	    if(ret!=0)
	    {
	        MSG_DISPLAY("Dequeue op %d \n",ret);

	        struct rte_mbuf *mbuf;
			mbuf = dequeued_op->sym->m_dst;
			MSG_DISPLAY("dequeue:out_mbuf0x%x\n", mbuf);
			MSG_DISPLAY("dequeued_op->sym->session0x%x\n", dequeued_op->sym->session);
	    }
    }while(!ret);
	
	rte_crypto_op_free(dequeued_op);
    rte_cryptodev_sym_session_clear(ctx->dev_id, sess[0]);
    rte_cryptodev_sym_session_free(sess[0]);
	
    return 0;
}


/*****************************************************************************
 * �������ƣ� zhijiang_sm4
 * ���������� ����
 * ���ʵı��� ��
 * �޸ĵı��� ��
 * ��������� inputָ����ܵ�λ�� in_len���ܵķ�Χ
 * ��������� �ޡ�
 * �� �� ֵ�� mbuf��������֤����Ѿ�����
 * ����˵���� ��      
 *****************************************************************************/
int zhijiang_sm4(struct rte_mbuf *mbuf, unsigned char *input, unsigned int in_len, unsigned int core_id, unsigned int enc)
{
	uint8_t *ptr = NULL;
	rsp_context_t ctx;
	int offset;
	int ret = 0;
	unsigned int flag;

	MSG_DISPLAY("%s %d \n",__FUNCTION__,__LINE__);

	if((NULL == mbuf)||(NULL == input))
	{
		ret |= 1;
		return ret;		
	}

	/* ptrָ��ǰ��Ч���ݵ��׵�ַ*/
	ptr = rte_pktmbuf_mtod(mbuf, uint8_t *);
	offset = (input - ptr);


	ctx.op = SM4_CBC;
	/* ���ܵ�ƫ�ƺͳ���,������8�ֽ�espͷ����1��16�ֽ�iv�ֶ� */
	ctx.c_offset = offset;
	ctx.c_size = in_len;
	
	ctx.qp_id		 = core_id;
	ctx.dev_id		 = mc_dev_id;
	ctx.socket_id	 = mc_socket_id;
	ctx.iv			 = test_iv;

	if (open_dbg) {
		MSG_DISPLAY("SM4 ctx.c_size:%d ctx.c_offset:%d\n", ctx.c_size, ctx.c_offset);
		softMemPrint((ptr+ctx.c_offset), ctx.c_size);
	}

	if(0 == enc)
	{
		flag = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	}
	else
	{
		flag = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	}
	
	ret = test_cipher_running(&ctx, mbuf, mbuf, flag);
	if(ret)
	{
		MSG_DISPLAY("encry err!!!");
		ret |= 2;
		return ret;
	}
	
	return 0;
}

/*****************************************************************************
 * �������ƣ� zhijiang_encry
 * ���������� ����
 * ���ʵı��� ��
 * �޸ĵı��� ��
 * ��������� inputָ��espͷ��ʼλ�� in_len��֤�ķ�Χ
 * ��������� �ޡ�
 * �� �� ֵ�� mbuf��������֤����Ѿ�����
 * ����˵���� ��      
 *****************************************************************************/
int zhijiang_encry(struct rte_mbuf *mbuf, unsigned char *input, unsigned int in_len, unsigned int core_id)
{
	uint8_t *ptr = NULL;
	rsp_context_t ctx;
	int offset;
	int ret = 0;

	MSG_DISPLAY("%s %d \n",__FUNCTION__,__LINE__);

	if((NULL == mbuf)||(NULL == input))
	{
		ret |= 1;
		return ret;		
	}

	/* ptrָ��ǰ��Ч���ݵ��׵�ַ*/
	ptr = rte_pktmbuf_mtod(mbuf, uint8_t *);
	offset = (input - ptr);


	/* ��ʽ�㷨 */
	ctx.op = SM4_SM3;
	/* hash��ƫ�ƺͳ���.��Χ����espͷ��iv�ֶ� */
	ctx.a_offset = offset;
	ctx.a_size = in_len;
	/* ���ܵ�ƫ�ƺͳ���,������8�ֽ�espͷ����1��16�ֽ�iv�ֶ� */
	ctx.c_offset = offset + ESP_HEADER_LEN + IV_LEN;
	ctx.c_size = in_len - (ESP_HEADER_LEN + IV_LEN);

	if (open_dbg) {
		MSG_DISPLAY("SM4_SM3 ctx.a_size:%d ctx.a_offset:%d\n", ctx.a_size, ctx.a_offset);
		softMemPrint((ptr+ctx.a_offset), ctx.a_size);
		MSG_DISPLAY("SM4_SM3 ctx.c_size:%d ctx.c_offset:%d\n", ctx.c_size, ctx.c_offset);
		softMemPrint((ptr+ctx.c_offset), ctx.c_size);

	}
	ctx.qp_id		 = core_id;
	ctx.dev_id		 = mc_dev_id;
	ctx.socket_id	 = mc_socket_id;
	ctx.iv			 = test_iv;

	ret = test_cipher_running(&ctx, mbuf, mbuf, RTE_CRYPTO_CIPHER_OP_ENCRYPT);
	if(ret)
	{
		MSG_DISPLAY("encry err!!!");
		ret |= 2;
		return ret;
	}
	return 0;
}


/*****************************************************************************
 * �������ƣ� zhijiang_encry
 * ���������� ����
 * ���ʵı��� ��
 * �޸ĵı��� ��
 * ��������� inputָ��espͷ��ʼλ�� in_len��֤�ķ�Χ
 * ��������� �ޡ�
 * �� �� ֵ�� mbuf��������֤����Ѿ�����
 * ����˵���� ��      
 *****************************************************************************/
int zhijiang_decry(struct rte_mbuf *mbuf, unsigned char *input, unsigned int in_len, unsigned int core_id)
{
	uint8_t *ptr = NULL;
	rsp_context_t ctx;
	int offset;
	int ret = 0;

	MSG_DISPLAY("%s %d \n",__FUNCTION__,__LINE__);

	if((NULL == mbuf)||(NULL == input))
	{
		ret |= 1;
		return ret;		
	}

	/* ptrָ��ǰ��Ч���ݵ��׵�ַ*/
	ptr = rte_pktmbuf_mtod(mbuf, uint8_t *);
	offset = (input - ptr);


	/* ��ʽ�㷨 */
	ctx.op = SM4_SM3;
	/* hash��ƫ�ƺͳ���.��Χ����espͷ��iv�ֶ� */
	ctx.a_offset = offset;
	ctx.a_size = in_len;
	/* ���ܵ�ƫ�ƺͳ���,������8�ֽ�espͷ����1��16�ֽ�iv�ֶ� */
	ctx.c_offset = offset + ESP_HEADER_LEN + IV_LEN;
	ctx.c_size = in_len - (ESP_HEADER_LEN + IV_LEN);

	if (open_dbg) {
		MSG_DISPLAY("SM3_SM4 ctx.a_size:%d ctx.a_offset:%d\n", ctx.a_size, ctx.a_offset);
		softMemPrint((ptr+ctx.a_offset), ctx.a_size);
		MSG_DISPLAY("SM3_SM4 ctx.c_size:%d ctx.c_offset:%d\n", ctx.c_size, ctx.c_offset);
		softMemPrint((ptr+ctx.c_offset), ctx.c_size);

	}
	ctx.qp_id		 = core_id;
	ctx.dev_id		 = mc_dev_id;
	ctx.socket_id	 = mc_socket_id;
	ctx.iv			 = test_iv;


	ret = test_cipher_running(&ctx, mbuf, mbuf, RTE_CRYPTO_CIPHER_OP_DECRYPT);
	if(ret)
	{
		MSG_DISPLAY("decry err!!!");
		ret |= 2;
		return ret;
	}
	
	return 0;
}



int alg_test(uint32_t flag)
{	
	int ret = 0;
	rsp_context_t ctx;
	struct rte_mempool *mbuf_pool;
	struct rte_mbuf *in_mbuf;
	struct rte_mbuf *out_mbuf;
	uint8_t *ptr;

	ret = zhijiang_init_crypto_device();
	if(ret)
	{
		MSG_DISPLAY("device init fail!\n ");
		ret |= 8;
		return ret;
	}

	/* ��ʼ��������Ϣ */
    mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool_test1",
                            RSP_MAX_DEPTH*2,
                            0,
                            0,
                            MAX_MBUF_SIZE,//data room size include head(128)
                            mc_socket_id);
	if(NULL == mbuf_pool)
	{
		MSG_DISPLAY("in mbuf pool alloc fail!\n ");
		ret |= 8;
		return ret;
	}

	ret = rte_pktmbuf_alloc_bulk(mbuf_pool, &in_mbuf, 1);
	if(ret)
	{
		MSG_DISPLAY("in mbuf alloc fail!\n ");
		ret |= 1;
		return ret;
	}
	
	ret = rte_pktmbuf_alloc_bulk(mbuf_pool, &out_mbuf, 1);
	if(ret)
	{
		MSG_DISPLAY("out mbuf alloc fail!\n ");
		ret |= 2;
		return ret;
	}
	
	if(1 == flag)
	{
		ptr = rte_pktmbuf_mtod(in_mbuf, uint8_t *);
		memcpy(ptr,test_input, 64);
		zhijiang_sm4(in_mbuf, ptr, 64, 1, 1);
	}
	else
	{
		/* ��ʽ�㷨 */
		ctx.op = SM4_SM3;
		/* hash��ƫ�ƺͳ���.��Χ����espͷ��iv�ֶ� */
		ctx.a_offset = 0;
		ctx.a_size = (80+8);
		/* ���ܵ�ƫ�ƺͳ���,������8�ֽ�espͷ����1��16�ֽ�iv�ֶ� */
		ctx.c_offset = 8+16;
		ctx.c_size = 64;
		ctx.qp_id		 = 1;
		ctx.dev_id		 = mc_dev_id;
		ctx.socket_id	 = mc_socket_id;
		ctx.iv			 = test_iv;

		/* �õ�buf���ݵ���ָ�� ������Ҫ���ܵ����ݵ�ָ��λ�ã���ַ��Ҫ4�ֽڶ���*/
	    ptr = rte_pktmbuf_mtod(in_mbuf, uint8_t *);
		MSG_DISPLAY("hash data:\n");
		memcpy(ptr+ctx.a_offset,test_input3, ctx.a_size);
		
		MSG_DISPLAY("encry data:\n");
		softMemPrint(ptr+ctx.a_offset,(ctx.a_size + 32));

		/* SM4_SM3 */
		ret = test_cipher_running(&ctx, in_mbuf, out_mbuf, RTE_CRYPTO_CIPHER_OP_ENCRYPT);
		if(ret)
		{
			ret |= 4;
			rte_pktmbuf_free(in_mbuf);
			rte_pktmbuf_free(out_mbuf);
			return ret;
		}
	}
	
	rte_pktmbuf_free(in_mbuf);
	rte_pktmbuf_free(out_mbuf);
	
	return 0;
}

#endif


#if ZHIJIANG_READ("zhijiang")

void encrypt_with_payload(uint32_t *spi_addr, uint32_t *srcip_addr,uint32_t *dstip_addr,uint32_t hdrlen,SHORT_STDPARAMS) {
	
	if(spi_addr==NULL||srcip_addr==NULL||dstip_addr==NULL){
		MSG_DISPLAY("spi_addr,srcip_addr,dstip_addr is NULL\n");
		return;
	}

	if(hdrlen==0){
		MSG_DISPLAY("hdr_len is 0\n");
		return;
	}

	unsigned int ret = 0;
	unsigned int core_id;
	unsigned int node;
	unsigned int spi = 0;
	unsigned int srcip = 0xc0a80064;
	unsigned int dstip = 0xc0a800c8;
	memcpy(&spi,spi_addr,4);
	memcpy(&srcip,srcip_addr,4);
	memcpy(&dstip,dstip_addr,4);
	spi	  = rte_cpu_to_be_32(spi);
 	srcip = rte_cpu_to_be_32(srcip);
 	dstip = rte_cpu_to_be_32(dstip);
	MSG_DISPLAY("spi[0x%x],srcip[0x%x],dstip[0x%x]\n",spi,srcip,dstip);
    getcpu(&core_id,&node,NULL);
	
	ret = IPSec(pd->wrapper, spi, srcip, dstip, core_id);
	if(ret){
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
		MSG_DISPLAY("encry err! ret:0x%x\n", ret);
		return;
	}
	// pd->headers[header_instance_ethernet].pointer = pd->headers[header_instance_ethernet].pointer - (hdrlen+20+8+14);
	pd->headers[header_instance_ethernet].pointer -= (20 + 8 + 16);
	// pd->data = pd->data-(hdrlen+20+8);
	pd->emit_hdrinst_count = 1;
	pd->parsed_length = 14+(20 + 8 + 16);//(20 + 8 + 16):ip+esp+iv
	pd->emit_headers_length=pd->parsed_length;
	pd->payload_length = pd->wrapper->pkt_len - pd->emit_headers_length;
	MSG_DISPLAY("pd->emit_headers_length:%d\n", pd->emit_headers_length);
	debug("Called extern " T4LIT(encrypt_with_payload,extern) "\n");
}

void encrypt_with_payload_bySoftware(SHORT_STDPARAMS) {
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
    debug("Called extern " T4LIT(encrypt_with_payload_bySoftware,extern) "\n");
}


void decrypt_with_payload(SHORT_STDPARAMS){
	/* add by eqt */
	unsigned int ret = 0;
	unsigned int core_id;
	unsigned int node;
	getcpu(&core_id,&node,NULL);
	ret = unIPSec(pd->wrapper, core_id);

	pd->headers[header_instance_ethernet].pointer += 44;
	pd->data = pd->data+44;

	if(ret){
		MSG_DISPLAY("[%s:%d]\n",__FUNCTION__,__LINE__);
		MSG_DISPLAY("decry err! ret:0x%x\n", ret);
	}

    // TODO implement call to extern
    debug("    : Called extern " T4LIT(decrypt_with_payload,extern) "\n");
}


void decrypt_with_payload_bysoftware(SHORT_STDPARAMS){
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
    debug("    : Called extern " T4LIT(decrypt_with_payload_bysoftware,extern) "\n");
    
}
#endif

