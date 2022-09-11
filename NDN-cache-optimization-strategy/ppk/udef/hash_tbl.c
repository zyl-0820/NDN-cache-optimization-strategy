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



#if ZHIJIANG_READ("hash表相关")

/*****************************************************************************
 * 函数名称： init_hash
 * 功能描述： 表项初始化
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
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
 * 函数名称： hash
 * 功能描述： 键值做hash
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int zj_hash(unsigned int key)
{
	unsigned int index;
	index = key % MODEL;

	return index;
}

/*****************************************************************************
 * 函数名称：写hash表
 * 功能描述： 
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int zj_insert_hash(hashTbl *h, unsigned int key, unsigned int *index)
{

	*index = zj_hash(key);
	
	while(h->elem[*index] != NULLKEY)//不为空则冲突
	{
		*index = (*index +1 ) % MODEL;//线性探测
		if(HASH_SIZE == *index)//没有位置插入，返回错误
		{
			return UNSUCESS;
		}
	}
	
	h->elem[*index] = key;//直到有空位之后插入关键字

	return SUCESS;
	
}

/*****************************************************************************
 * 函数名称：查找key对应的索引
 * 功能描述： 
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int zj_search_hash(hashTbl *h, unsigned int key, unsigned int *index)
{

	*index = zj_hash(key);//求hash地址

	while(h->elem[*index] != key)//存储的值不是key则向后探测
	{
		*index = (*index + 1) % MODEL;//线性探测
		if((h->elem[*index] == NULLKEY) || (h->elem[*index] == zj_hash(key)))
		{
			return UNSUCESS;//后面没有数据或者循环回到原点，关键字不存在
		}
	}

	return SUCESS;
	
}

/*****************************************************************************
 * 函数名称： zj_delete_hash
 * 功能描述： 删除hash表节点
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int zj_delete_hash(hashTbl *h, unsigned int index)
{

	h->elem[index] = NULLKEY;

	return SUCESS;
	
}


#endif


#if ZHIJIANG_READ("根据ethertype查nextheadr")


/*****************************************************************************
 * 函数名称： init_nexthead
 * 功能描述： 结构体初始化
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
void init_nexthead(void)
{

	zj_init_hash(&zj_hash_tbl);
	memset((char *)zj_next_hdr_tbl, 0, sizeof(nextHdrTbl)*ETH_TBL_SIZE);
	
	return;
	
}


/*****************************************************************************
 * 函数名称： add_nexthead
 * 功能描述： 新增nexthead
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
 int add_nexthead(unsigned short eth_type, unsigned char next_head)
 {
 
  	int ret;
	unsigned int index;

	/* 插入索引 */
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
 * 函数名称： delete_nexthead
 * 功能描述： 删除nexthead
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
 int delete_nexthead(unsigned short eth_type)
 {
 
	int ret;
	unsigned int index;
	
  	/* 获取索引 */
	ret = zj_search_hash(&zj_hash_tbl, eth_type, &index);
	if(SUCESS != ret)
	{
		MSG_DISPLAY("delete nexthead index err!!!");
		return UNSUCESS;
	}

	/* 删除hash节点 */
	zj_delete_hash(&zj_hash_tbl, index);

 	zj_next_hdr_tbl[index].valid = false;
	zj_next_hdr_tbl[index].value = 0;
	
 	return SUCESS;
	
 }


/*****************************************************************************
 * 函数名称： update_nexthead
 * 功能描述： 更新nexthead
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
 int update_nexthead(unsigned short eth_type, unsigned char next_head)
 {

 	int ret;
	unsigned int index;
	
 	/* 获取索引 */
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
 * 函数名称： query_nexthead
 * 功能描述： 根据以太类型查找esp尾部封装的下一个头部字段
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int query_nexthead(unsigned short eth_type, unsigned char *next_head)
{

	int ret;
	unsigned int index;
	
	/* 获取索引 */
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


#if ZHIJIANG_READ("根据nextheadr查ethertype")


/*****************************************************************************
 * 函数名称： init_ethertype
 * 功能描述： 新增nexthead
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
void init_ethertype(void)
{

	zj_init_hash(&zj_hash_tbl2);
	memset((char *)zj_eth_tbl, 0, sizeof(ethTbl)*ETH_TBL_SIZE);
	
	return;
	
}


/*****************************************************************************
 * 函数名称： add_ethertype
 * 功能描述： 新增ethertype
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
 int add_ethertype(unsigned char next_head, unsigned short eth_type)
 {
 
  	int ret;
	unsigned int index;
	
 	/* 插入索引 */
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
 * 函数名称： delete_nexthead
 * 功能描述： 删除nexthead
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
 int delete_ethertype(unsigned char next_head)
 {
 
	int ret;
	unsigned int index;
	
  	/* 获取索引 */
	ret = zj_search_hash(&zj_hash_tbl2, next_head, &index);
	if(ret)
	{
		MSG_DISPLAY("delete ethertype index err!!!\n");
		return UNSUCESS;
	}

	/* 删除hash节点 */
	zj_delete_hash(&zj_hash_tbl2, index);
		
 	zj_eth_tbl[index].valid = false;
	zj_eth_tbl[index].value = 0;
	
 	return SUCESS;
	
 }


/*****************************************************************************
 * 函数名称： update_nexthead
 * 功能描述： 更新nexthead
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
 int update_ethertype(unsigned char next_head, unsigned short eth_type)
 {

 	int ret;
	unsigned int index;
	
 	/* 获取索引 */
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
 * 函数名称： query_ethertype
 * 功能描述： 根据以太类型查找esp尾部封装的下一个头部字段
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int query_ethertype(unsigned char next_head, unsigned short *eth_type)
{

	int ret;
	unsigned int index;
	
	/* 获取索引 */
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

