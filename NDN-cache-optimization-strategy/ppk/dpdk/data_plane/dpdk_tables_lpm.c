// Copyright 2016 Eotvos Lorand University, Budapest, Hungary
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


// This file is included directly from `dpdk_tables.c`.


struct rte_lpm* lpm4_create(int socketid, const char* name, int max_size)
{
#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0)  //dpdk 版本
    struct rte_lpm_config config = {
        .max_rules = max_size,
        .number_tbl8s = (1 << 8), // TODO refine this
        .flags = 0,
    };
    struct rte_lpm *l = rte_lpm_create(name, socketid, &config);
#else
    struct rte_lpm *l = rte_lpm_create(name, socketid, max_size, 0/*flags*/);
#endif
    if (l == NULL)
        create_error(socketid, "LPM", name);
    return l;
}

struct rte_lpm6* lpm6_create(int socketid, const char* name, int max_size)
{
    struct rte_lpm6_config config = {
        .max_rules = max_size,
        .number_tbl8s = (1 << 16),
        .flags = 0,
    };
    struct rte_lpm6 *l = rte_lpm6_create(name, socketid, &config);
    if (l == NULL)
        create_error(socketid, "LPM6", name);
    return l;
}


void lpm4_add(struct rte_lpm* l, uint32_t key, uint8_t depth, table_index_t value)
{
    int ret = rte_lpm_add(l, key, depth, value);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Unable to add entry to the LPM table\n");
}

void lpm6_add(struct rte_lpm6* l, uint8_t key[16], uint8_t depth, table_index_t value)
{
    int ret = rte_lpm6_add(l, key, depth, value);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Unable to add entry to the LPM table\n");
}


void lpm_create(lookup_table_t* t, int socketid)
{
    char name[64];
    snprintf(name, sizeof(name), "%d_lpm_%d_%d", t->id, socketid, t->instance);
    if(t->entry.key_size <= 4)
        create_ext_table(t, lpm4_create(socketid, name, t->max_size), socketid);
    else if(t->entry.key_size <= 16)
        create_ext_table(t, lpm6_create(socketid, name, t->max_size), socketid);
    else
        rte_exit(EXIT_FAILURE, "LPM: key_size not supported\n");

}


void lpm_add(lookup_table_t* t, uint8_t* key, uint8_t depth, uint8_t* value)
{
    if (t->entry.key_size == 0) return; // don't add lines to keyless tables

    extended_table_t* ext = (extended_table_t*)t->table;
    ext->content[ext->size] = make_table_entry_on_socket(t, value);
    if (t->entry.key_size <= 4)
    {
        // the rest is zeroed in case of keys smaller than 4 bytes
        uint32_t key32 = 0;
        memcpy(&key32, key, t->entry.key_size);

        lpm4_add(ext->rte_table, key32, depth, ext->size++);
    }
    else if (t->entry.key_size <= 16)
    {
        static uint8_t key128[16];
        memset(key128, 0, 16);
        memcpy(key128, key, t->entry.key_size);

        lpm6_add(ext->rte_table, key128, depth, ext->size++);
    }
}


uint8_t* lpm_lookup(lookup_table_t* t, uint8_t* key)
{
    if (t->entry.key_size == 0) return t->default_val;
    extended_table_t* ext = (extended_table_t*)t->table;

    if(t->entry.key_size <= 4)
    {
        uint32_t key32 = 0;
        memcpy(&key32, key, t->entry.key_size);

        table_index_t result;
#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0) //dpdk版本号
        uint32_t result32;
        int ret = rte_lpm_lookup(ext->rte_table, key32, &result32);  //查表，命中则返回0； result32为该IP对应的下一跳
        result = (table_index_t)result32;
#else
        int ret = rte_lpm_lookup(ext->rte_table, key32, &result);
#endif 
        return ret == 0 ? ext->content[result] : t->default_val;
    }
    else if(t->entry.key_size <= 16)
    {
        static uint8_t key128[16];
        memset(key128, 0, 16);
        memcpy(key128, key, t->entry.key_size);

        table_index_t result;
        int ret = rte_lpm6_lookup(ext->rte_table, key128, &result);
        return ret == 0 ? ext->content[result] : t->default_val;
    }
    return NULL;
}


void lpm_flush(lookup_table_t* t)
{
    extended_table_t* ext = (extended_table_t*)t->table;
    rte_free(ext->content[ext->size]);
    if (t->entry.key_size <= 4)
    {
        rte_lpm_delete_all(ext->rte_table);
    }
    else if (t->entry.key_size <= 16)
    {
        rte_lpm6_delete_all(ext->rte_table);
    }
}

//////////////////////Xiajiqiang 2020/09/22//////////////////
/*
void lpm_delete(lookup_table_t* t, uint8_t* key)
{
    if (t->entry.key_size == 0) return; // nothing must have been added
    extended_table_t* ext = (extended_table_t*)t->table;

        if(t->entry.key_size <= 4) //entry.key_size为IP地址长度
    {
        uint32_t key32 = 0;
        memcpy(&key32, key, t->entry.key_size);

        table_index_t result;
#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0) //dpdk版本号
        uint32_t result32;
        int ret = rte_lpm_lookup(ext->rte_table, key32, &result32);  //查表，命中则返回0； result32为该IP对应的下一跳
        result = (table_index_t)result32;
#else
        int ret = rte_lpm_lookup(ext->rte_table, key32, &result);
#endif
    }
    else if(t->entry.key_size <= 16)
    {
        static uint8_t key128[16];
        memset(key128, 0, 16);
        memcpy(key128, key, t->entry.key_size);

        table_index_t result;
        int ret = rte_lpm6_lookup(ext->rte_table, key128, &result);
    }
    if (ret == 0) //命中
        rte_free(ext->content[result]); 
}
*/
//////////////////////Xiajiqiang 2020/09/22//////////////////
// void lpm_delete(lookup_table_t* t, uint8_t* key, uint8_t depth)
// {
//     if (t->entry.key_size == 0) return; 

//     extended_table_t* ext = (extended_table_t*)t->table;
//     int ret = rte_lpm_delete(ext->rte_table, key, depth); //rte_lpm_delete: Delete a rule from the LPM table.
//     if (ret<0)
//          rte_exit(EXIT_FAILURE, "Unable to delete this entry from the LPM table\n"); 
// }
//////////////////////Xiajiqiang 2020/09/22//////////////////

//////////////////////Xiajiqiang 2020/09/22//////////////////
#if 1
void lpm_delete(lookup_table_t* t, uint8_t* key, uint8_t depth)
{
    if (t->entry.key_size == 0) return; // nothing must have been added
    extended_table_t* ext = (extended_table_t*)t->table;

//        if(t->entry.key_size <= 4) //entry.key_size为IP地址长度
 //   {
        uint32_t key32 = 0;
        memcpy(&key32, key, t->entry.key_size);

        table_index_t result;
//#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0) //dpdk版本号
        uint32_t result32;
        int ret  = rte_lpm_lookup(ext->rte_table, key32, &result32);  //查表，命中则返回0； result32为该IP对应的下一跳
        result = (table_index_t)result32;
//#else
//        int ret = rte_lpm_lookup(ext->rte_table, key32, &result);
//#endif
//    }
     if (ret == 0) {//命中
        rte_lpm_delete(ext->rte_table, key32, depth);
        rte_free(ext->content[result]);
        //rte_lpm_free(ext->rte_table);
     }
}

#endif
#if 0
//////////////////////Xiajiqiang 2020/09/22//////////////////
void lpm_delete(lookup_table_t* t, uint8_t* key, uint8_t depth)
{
    printf("----------------------------------------LPM_DELETE-------------------------------");
    if (t->entry.key_size == 0) return; 
    uint32_t key32 = 0;
    memcpy(&key32, key, t->entry.key_size);
    extended_table_t* ext = (extended_table_t*)t->table;
    int ret = rte_lpm_delete(ext->rte_table, key32, depth); //rte_lpm_delete: Delete a rule from the LPM table.
    if (ret == 0)
	rte_free(ext->content[ext->size]);
        //rte_lpm_free(ext->rte_table); 
    if (ret<0)
        rte_exit(EXIT_FAILURE, "Unable to delete this entry from the LPM table\n"); 
}
#endif
