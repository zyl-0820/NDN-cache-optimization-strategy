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

#ifndef __UTIL_H_
#define __UTIL_H_

#include <stdint.h>
#include <stdio.h>
#include <rte_common.h>
#include <pthread.h>
#include "gen_include.h"

#define T4COLOR(color)    "\e[" color "m"

#ifndef T4LIGHT_off
    #define T4LIGHT_off
#endif

#ifndef T4LIGHT_default
    #define T4LIT(txt,...)      #txt
    #define T4LIGHT_default
#else
    #define T4LIT(txt,...)      "\e[" T4LIGHT_##__VA_ARGS__ "m" #txt "\e[" T4LIGHT_off "m"
#endif

#define T4LIGHT_ T4LIGHT_default


#ifdef PPK_DEBUG
    extern void dbg_fprint_bytes(FILE* out_file, void* bytes, int byte_count);
    extern pthread_mutex_t dbg_mutex;

    #define __SHORTFILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

    #define dbg_bytes(bytes, byte_count, MSG, ...)   \
        { \
            pthread_mutex_lock(&dbg_mutex); \
            debug_printf(MSG T4COLOR(T4LIGHT_bytes), ##__VA_ARGS__); \
            dbg_fprint_bytes(stderr, bytes, byte_count); \
            fprintf(stderr, T4COLOR(T4LIGHT_off) "\n"); \
            pthread_mutex_unlock(&dbg_mutex); \
        }
#else
    #define dbg_bytes(bytes, byte_count, MSG, ...)   
#endif



void sleep_millis(int millis);


#endif
