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
#ifndef __ALIASES_H_
#define __ALIASES_H_

#include <rte_mbuf.h>
typedef struct rte_mbuf packet;

typedef uint8_t packet_data_t;

#include <rte_spinlock.h>
typedef rte_spinlock_t lock_t;

#define INVALID_TABLE_ENTRY false
#define VALID_TABLE_ENTRY   true

#endif // __ALIASES_H_

