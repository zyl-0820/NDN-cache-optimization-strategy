#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_tbl.h"
#include "sa_tbl.h"

#define SA_TBL_SIZE 512



SA_TBL zj_sa_tbl[SA_TBL_SIZE];

hashTbl zj_hash_tbl3;


/*****************************************************************************
 * 函数名称： init_sa
 * 功能描述： sa表项初始化
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
void init_sa(void)
{

	zj_init_hash(&zj_hash_tbl3);
	memset((char *)zj_sa_tbl, 0, sizeof(SA_TBL)*SA_TBL_SIZE);
	
	return;
}


/*****************************************************************************
 * 函数名称： add_sa
 * 功能描述： sa表项新增
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int add_sa(unsigned int spi, unsigned int lifetime, unsigned int mode, unsigned char encry_alg, char* cipher_key, unsigned int vector1, unsigned char hash_alg, char* hash_key, unsigned int vector2, unsigned int mtu)
{

  	int ret;
	unsigned int index;

	/* 插入索引 */
	ret = zj_insert_hash(&zj_hash_tbl3, spi, &index);
	if(SUCESS != ret)
	{
		return UNSUCESS;
	}

	MSG_DISPLAY("add_sa index:%d\n", index);

	zj_sa_tbl[index].spi = spi;
	zj_sa_tbl[index].life_time = lifetime;
	zj_sa_tbl[index].mtu = mtu;
	zj_sa_tbl[index].encry_alg = encry_alg;
	zj_sa_tbl[index].hash_alg = hash_alg;
	zj_sa_tbl[index].iv_len = IV_LEN;


	memcpy((char *)zj_sa_tbl[index].cipher_key, cipher_key, CIPHER_KEY_LEN);
	memcpy((char *)zj_sa_tbl[index].hash_key, hash_key, HASH_KEY_LEN);

	zj_sa_tbl[index].valid = 1;
	
 	return SUCESS;
	
}

/*****************************************************************************
 * 函数名称： update_sa
 * 功能描述： sa表项更新
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int update_sa(unsigned int spi, unsigned int lifetime, unsigned int mode, unsigned char encry_alg, char* cipher_key, unsigned int vector1, unsigned char hash_alg, char* hash_key, unsigned int vector2, unsigned int mtu)
{

 	int ret;
	unsigned int index;
	
 	/* 获取索引 */
	ret = zj_search_hash(&zj_hash_tbl3, spi, &index);
	if(SUCESS != ret)
	{
		return UNSUCESS;
	}

	if(0 == zj_sa_tbl[index].valid)
	{
		return UNSUCESS;
	}
	
	zj_sa_tbl[index].spi = spi;
	zj_sa_tbl[index].life_time = lifetime;
	zj_sa_tbl[index].mtu = mtu;
	zj_sa_tbl[index].encry_alg = encry_alg;
	zj_sa_tbl[index].hash_alg = hash_alg;
	zj_sa_tbl[index].iv_len = IV_LEN;


	memcpy((char *)zj_sa_tbl[index].cipher_key, cipher_key, CIPHER_KEY_LEN);
	memcpy((char *)zj_sa_tbl[index].hash_key, hash_key, HASH_KEY_LEN);

	
 	return SUCESS;

	
}

/*****************************************************************************
 * 函数名称： query_sa
 * 功能描述： sa表项查找
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int query_sa(unsigned int spi, SA_TBL **ipsec_sa)
{
 	int ret;
	unsigned int index;
	
 	/* 获取索引 */
	ret = zj_search_hash(&zj_hash_tbl3, spi, &index);
	if(SUCESS != ret)
	{
		return UNSUCESS;
	}

	*ipsec_sa = &zj_sa_tbl[index];

	return SUCESS;
}


/*****************************************************************************
 * 函数名称： delete_sa
 * 功能描述： sa表项删除
 * 访问的表： 无
 * 修改的表： 无
 * 输入参数： 
 * 输出参数： 无。
 * 返 回 值： 
 * 其它说明： 无      
 *****************************************************************************/
int delete_sa(unsigned int spi)
{
	int ret;
	unsigned int index;
	
  	/* 获取索引 */
	ret = zj_search_hash(&zj_hash_tbl3, spi, &index);
	if(SUCESS != ret)
	{
		return UNSUCESS;
	}

	/* 删除hash节点 */
	zj_delete_hash(&zj_hash_tbl3, index);

 	memset((char *)&zj_sa_tbl[index], 0, sizeof(SA_TBL));
	
 	return SUCESS;

}


