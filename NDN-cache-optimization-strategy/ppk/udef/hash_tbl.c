#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "hash_tbl.h"

#define HASH_SIZE 512
#define NULLKEY -32768
#define MODEL 511
#define ETH_TBL_SIZE 512


typedef struct next_hdr_tbl{
	bool valid;
	unsigned char value;
}nextHdrTbl;


typedef struct eth_tbl{
	bool valid;
	unsigned short value;
}ethTbl;


nextHdrTbl zj_next_hdr_tbl[ETH_TBL_SIZE];

ethTbl zj_eth_tbl[ETH_TBL_SIZE];


hashTbl zj_hash_tbl;

hashTbl zj_hash_tbl2;


#define ZHIJIANG_READ(X) 1



#if ZHIJIANG_READ("hash�����")

/*****************************************************************************
 * �������ƣ� init_hash
 * ���������� �����ʼ��
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
int zj_init_hash(hashTbl *h)
{
	
	int i;
	h->count = HASH_SIZE;
	h->elem = (int *)malloc(HASH_SIZE * sizeof(int));

	for(i = 0; i < HASH_SIZE; i++)
	{
		h->elem[i] = NULLKEY;
	}

	return SUCESS;

}


/*****************************************************************************
 * �������ƣ� hash
 * ���������� ��ֵ��hash
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
int zj_hash(unsigned int key)
{
	unsigned int index;
	index = key % MODEL;

	return index;
}

/*****************************************************************************
 * �������ƣ�дhash��
 * ���������� 
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
int zj_insert_hash(hashTbl *h, unsigned int key, unsigned int *index)
{

	*index = zj_hash(key);
	
	while(h->elem[*index] != NULLKEY)//��Ϊ�����ͻ
	{
		*index = (*index +1 ) % MODEL;//����̽��
		if(HASH_SIZE == *index)//û��λ�ò��룬���ش���
		{
			return UNSUCESS;
		}
	}
	
	h->elem[*index] = key;//ֱ���п�λ֮�����ؼ���

	return SUCESS;
	
}

/*****************************************************************************
 * �������ƣ�����key��Ӧ������
 * ���������� 
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
int zj_search_hash(hashTbl *h, unsigned int key, unsigned int *index)
{

	*index = zj_hash(key);//��hash��ַ

	while(h->elem[*index] != key)//�洢��ֵ����key�����̽��
	{
		*index = (*index + 1) % MODEL;//����̽��
		if((h->elem[*index] == NULLKEY) || (h->elem[*index] == zj_hash(key)))
		{
			return UNSUCESS;//����û�����ݻ���ѭ���ص�ԭ�㣬�ؼ��ֲ�����
		}
	}

	return SUCESS;
	
}

/*****************************************************************************
 * �������ƣ� zj_delete_hash
 * ���������� ɾ��hash��ڵ�
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� ��
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
int zj_delete_hash(hashTbl *h, unsigned int index)
{

	h->elem[index] = NULLKEY;

	return SUCESS;
	
}


#endif


#if ZHIJIANG_READ("����ethertype��nextheadr")


/*****************************************************************************
 * �������ƣ� init_nexthead
 * ���������� �ṹ���ʼ��
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
void init_nexthead(void)
{

	zj_init_hash(&zj_hash_tbl);
	memset((char *)zj_next_hdr_tbl, 0, sizeof(nextHdrTbl)*ETH_TBL_SIZE);
	
	return;
	
}


/*****************************************************************************
 * �������ƣ� add_nexthead
 * ���������� ����nexthead
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
 int add_nexthead(unsigned short eth_type, unsigned char next_head)
 {
 
  	int ret;
	unsigned int index;

	/* �������� */
	ret = zj_insert_hash(&zj_hash_tbl, eth_type, &index);
	if(SUCESS != ret)
	{
		MSG_DISPLAY("insert nexthead index err!!!\n");
		return UNSUCESS;
	}

	MSG_DISPLAY("add_nexthead index:%d\n", index);
	MSG_DISPLAY("add_nexthead next_head:0x%x\n", next_head);
	
	zj_next_hdr_tbl[index].value = next_head;
	zj_next_hdr_tbl[index].valid = true;

	MSG_DISPLAY("zj_next_hdr_tbl[index].value:0x%x\n", zj_next_hdr_tbl[index].value);
	
 	return SUCESS;
	
 }

/*****************************************************************************
 * �������ƣ� delete_nexthead
 * ���������� ɾ��nexthead
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
 int delete_nexthead(unsigned short eth_type)
 {
 
	int ret;
	unsigned int index;
	
  	/* ��ȡ���� */
	ret = zj_search_hash(&zj_hash_tbl, eth_type, &index);
	if(SUCESS != ret)
	{
		MSG_DISPLAY("delete nexthead index err!!!");
		return UNSUCESS;
	}

	/* ɾ��hash�ڵ� */
	zj_delete_hash(&zj_hash_tbl, index);

 	zj_next_hdr_tbl[index].valid = false;
	zj_next_hdr_tbl[index].value = 0;
	
 	return SUCESS;
	
 }


/*****************************************************************************
 * �������ƣ� update_nexthead
 * ���������� ����nexthead
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
 int update_nexthead(unsigned short eth_type, unsigned char next_head)
 {

 	int ret;
	unsigned int index;
	
 	/* ��ȡ���� */
	ret = zj_search_hash(&zj_hash_tbl, eth_type, &index);
	if(SUCESS != ret)
	{
		MSG_DISPLAY("update nexthead index err!!!\n");
		return UNSUCESS;
	}
	
	zj_next_hdr_tbl[index].value = next_head;
	
 	return SUCESS;
	
 }

/*****************************************************************************
 * �������ƣ� query_nexthead
 * ���������� ������̫���Ͳ���espβ����װ����һ��ͷ���ֶ�
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
int query_nexthead(unsigned short eth_type, unsigned char *next_head)
{

	int ret;
	unsigned int index;
	
	/* ��ȡ���� */
	ret = zj_search_hash(&zj_hash_tbl, eth_type, &index);
	if(ret)
	{
		MSG_DISPLAY("nexthead index err!!!\n");
		return UNSUCESS;
	}

	if(false == zj_next_hdr_tbl[index].valid)
	{
		MSG_DISPLAY("nexthead tbl invalid!!!\n");
		return UNSUCESS;
	}
	
	*next_head = zj_next_hdr_tbl[index].value;
	
	return SUCESS;
	
}


#endif


#if ZHIJIANG_READ("����nextheadr��ethertype")


/*****************************************************************************
 * �������ƣ� init_ethertype
 * ���������� ����nexthead
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
void init_ethertype(void)
{

	zj_init_hash(&zj_hash_tbl2);
	memset((char *)zj_eth_tbl, 0, sizeof(ethTbl)*ETH_TBL_SIZE);
	
	return;
	
}


/*****************************************************************************
 * �������ƣ� add_ethertype
 * ���������� ����ethertype
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
 int add_ethertype(unsigned char next_head, unsigned short eth_type)
 {
 
  	int ret;
	unsigned int index;
	
 	/* �������� */
	ret = zj_insert_hash(&zj_hash_tbl2, next_head, &index);
	if(SUCESS != ret)
	{
		MSG_DISPLAY("insert ethertype index err!!!\n");
		return UNSUCESS;
	}

	MSG_DISPLAY("add_ethertype index:%d\n", index);
	MSG_DISPLAY("add_ethertype eth_type:0x%x\n", eth_type);
	
	zj_eth_tbl[index].value = eth_type;
	zj_eth_tbl[index].valid = true;

	MSG_DISPLAY("zj_eth_tbl[index].value:0x%x\n", zj_eth_tbl[index].value);
	
 	return SUCESS;
	
 }

/*****************************************************************************
 * �������ƣ� delete_nexthead
 * ���������� ɾ��nexthead
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
 int delete_ethertype(unsigned char next_head)
 {
 
	int ret;
	unsigned int index;
	
  	/* ��ȡ���� */
	ret = zj_search_hash(&zj_hash_tbl2, next_head, &index);
	if(ret)
	{
		MSG_DISPLAY("delete ethertype index err!!!\n");
		return UNSUCESS;
	}

	/* ɾ��hash�ڵ� */
	zj_delete_hash(&zj_hash_tbl2, index);
		
 	zj_eth_tbl[index].valid = false;
	zj_eth_tbl[index].value = 0;
	
 	return SUCESS;
	
 }


/*****************************************************************************
 * �������ƣ� update_nexthead
 * ���������� ����nexthead
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
 int update_ethertype(unsigned char next_head, unsigned short eth_type)
 {

 	int ret;
	unsigned int index;
	
 	/* ��ȡ���� */
	ret = zj_search_hash(&zj_hash_tbl2, next_head, &index);
	if(ret)
	{
		MSG_DISPLAY("update ethertype index err!!!\n");
		return UNSUCESS;
	}
	
	zj_eth_tbl[index].value = eth_type;
	
 	return SUCESS;
	
 }

/*****************************************************************************
 * �������ƣ� query_ethertype
 * ���������� ������̫���Ͳ���espβ����װ����һ��ͷ���ֶ�
 * ���ʵı� ��
 * �޸ĵı� ��
 * ��������� 
 * ��������� �ޡ�
 * �� �� ֵ�� 
 * ����˵���� ��      
 *****************************************************************************/
int query_ethertype(unsigned char next_head, unsigned short *eth_type)
{

	int ret;
	unsigned int index;
	
	/* ��ȡ���� */
	ret = zj_search_hash(&zj_hash_tbl2, next_head, &index);
	if(ret)
	{
		MSG_DISPLAY("update ethertype index err!!!\n");
		return UNSUCESS;
	}

	MSG_DISPLAY("query_ethertype index:%d\n", index);

	if(false == zj_eth_tbl[index].valid)
	{
		MSG_DISPLAY("ethertype tbl invalid !!!\n");
		return UNSUCESS;
	}
	
	*eth_type = zj_eth_tbl[index].value;
	
	return SUCESS;
	
}



#endif

