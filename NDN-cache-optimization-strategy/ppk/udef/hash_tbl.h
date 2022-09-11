#ifndef __HASH_TBL_H__
#define __HASH_TBL_H__

typedef struct hash_tbl{
	int *elem;//存放数据首地址
	int count;//总共多少个数据
}hashTbl;

#define SUCESS 0
#define UNSUCESS -1


extern int zj_init_hash(hashTbl *h);
extern int zj_hash(unsigned int key);
extern int zj_insert_hash(hashTbl *h, unsigned int key, unsigned int *index);
extern int zj_search_hash(hashTbl *h, unsigned int key, unsigned int *index);
extern int zj_delete_hash(hashTbl *h, unsigned int index);

extern void init_nexthead(void);
extern int add_nexthead(unsigned short eth_type, unsigned char next_head);
extern int delete_nexthead(unsigned short eth_type); 
extern int update_nexthead(unsigned short eth_type, unsigned char next_head);
extern int query_nexthead(unsigned short eth_type, unsigned char *next_head);


extern void init_ethertype(void);
extern int add_ethertype(unsigned char next_head, unsigned short eth_type);
extern int delete_ethertype(unsigned char next_head);
extern int update_ethertype(unsigned char next_head, unsigned short eth_type);
extern int query_ethertype(unsigned char next_head, unsigned short *eth_type);


#endif

