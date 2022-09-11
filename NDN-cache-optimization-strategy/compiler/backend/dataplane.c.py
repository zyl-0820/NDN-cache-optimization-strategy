# Copyright 2016 Eotvos Lorand University, Budapest, Hungary
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from utils.codegen import format_declaration, format_statement, format_expr, format_type, type_env
from utils.misc import addError, addWarning

#[ #include <stdlib.h>
#[ #include <string.h>
#[ #include <stdbool.h>
#[ #include "dpdk_lib.h"
#[ #include "actions.h"
#[ #include "backend.h"
#[ #include "util.h"
#[ #include "util_packet.h"
#[ #include "tables.h"

#[ uint8_t* emit_addr;
#[ uint32_t ingress_pkt_len;

#[ extern ctrl_plane_backend bg;
#[ extern char* action_names[];

#[ extern void parse_packet(STDPARAMS);
#[ extern void increase_counter(int counterid, int index);
#[ extern void set_handle_packet_metadata(packet_descriptor_t* pd, uint32_t portid);

# note: 0 is for the special case where there are no tables
max_key_length = max([t.key_length_bytes for t in hlir16.tables if hasattr(t, 'key')] + [0])
#[ uint8_t reverse_buffer[${max_key_length}];

################################################################################

packet_name = hlir16.p4_main.type.baseType.type_ref.name
pipeline_elements = hlir16.p4_main.arguments

if hlir16.p4_model == 'V1Switch':
    p4_ctls = [ctl for pe in pipeline_elements for ctl in [hlir16.objects.get(pe.expression.type.name, 'P4Control')] if ctl is not None]
elif hlir16.p4_model == 'PSA_Switch':
    parsers_controls = [hlir16.objects.get(arg2.expression.type.name, ['P4Control', 'P4Parser'])
        for arg in hlir16.p4_main.arguments
        if arg.expression.node_type == "PathExpression" # ignoring PacketReplicationEngine and BufferingQueueingEngine for now
        for arg2 in arg.expression.ref.arguments
        ]

    p4_ctls = [pc for pc in parsers_controls if pc.node_type == 'P4Control']
else:
    # if the P4 model is unknown, it would already be detected
    pass


#{ struct apply_result_s {
#[     bool hit;
#[     enum actions action_run;
#} };

for ctl in p4_ctls:
    #[ void control_${ctl.name}(STDPARAMS);
    for t in ctl.controlLocals['P4Table']:
        #[ struct apply_result_s ${t.name}_apply(STDPARAMS);

################################################################################

# TODO move this to HAL
def match_type_order(t):
    if t == 'EXACT':   return 0
    if t == 'LPM':     return 1
    if t == 'TERNARY': return 2
    else:              return 3

################################################################################
# Table key calculation

for table in hlir16.tables:
    if not hasattr(table, 'key'):
        continue

    #{ void table_${table.name}_key(packet_descriptor_t* pd, uint8_t* key) {
    sortedfields = sorted(table.key.keyElements, key=lambda k: match_type_order(k.match_type))
    #TODO variable length fields
    #TODO field masks
    for f in sortedfields:
        if f.get_attr('width') is None:
            addError('Computing key for table', 'the width attribute of field {} is missing'.format(f.name))
            continue

        hi_name = "all_metadatas" if f.header_name in ['standard_metadata'] else f.header.name
        href = "header_instance_{}".format(hi_name)
        # fref = "field_{}_{}".format(f.header_name, f.field_name)
        fref = "field_{}_{}".format(f.header.type.type_ref.name, f.field_name)

        if f.width <= 32:
            byte_width = (f.width+7)/8
            #{ #ifdef PPK_DEBUG
            #{     if (unlikely(pd->headers[header_instance_${hi_name}].pointer == NULL)) {
            #[         debug(" " T4LIT(!!!!,error) " " T4LIT(Lookup on invalid header,error) " " T4LIT(${hi_name},header) "." T4LIT(${f.field_name},field) "\n");
            #}     }
            #} #endif
            #[ EXTRACT_INT32_BITS_PACKET(pd, $href, $fref, *(uint32_t*)key)
            #[ key += ${byte_width};
        elif f.width > 32 and f.width % 8 == 0:
            byte_width = (f.width+7)/8
            #[ EXTRACT_BYTEBUF_PACKET(pd, $href, $fref, key)
            #[ key += ${byte_width};
        else:
            addWarning("table key calculation", "Skipping unsupported field {} ({} bits): it is over 32 bits long and not byte aligned".format(f.id, f.width))

    if table.match_type == "LPM":
        #[ key -= ${table.key_length_bytes};
        #[ int c, d;
        #[ for(c = ${table.key_length_bytes-1}, d = 0; c >= 0; c--, d++) *(reverse_buffer+d) = *(key+c);
        #[ for(c = 0; c < ${table.key_length_bytes}; c++) *(key+c) = *(reverse_buffer+c);
    #} }

################################################################################
# Table application

def unique_stable(items):
    """Returns only the first occurrence of the items in a list.
    Equivalent to unique_everseen from Python 3."""
    from collections import OrderedDict
    return list(OrderedDict.fromkeys(items))


for type in unique_stable([comp['type'] for table in hlir16.tables for smem in table.direct_meters + table.direct_counters for comp in smem.components]):
    #[ void apply_direct_smem_$type(register_uint32_t* smem, uint32_t value, char* table_name, char* smem_type_name, char* smem_name) {
    #[    debug("     : applying apply_direct_smem_$type(register_uint32_t (*smem)[1], uint32_t value, char* table_name, char* smem_type_name, char* smem_name)");
    #[ }


for table in hlir16.tables:
    lookupfun = {'LPM':'lpm_lookup', 'EXACT':'exact_lookup', 'TERNARY':'ternary_lookup'}
    #[ struct apply_result_s ${table.name}_apply(STDPARAMS)
    #{ {
    if hasattr(table, 'key'):
        #[     uint8_t* key[${table.key_length_bytes}];
        #[     table_${table.name}_key(pd, (uint8_t*)key);

        #[     dbg_bytes(key, table_config[TABLE_${table.name}].entry.key_size,
        #[               " " T4LIT(????,table) " Table lookup $$[table]{table.name}/" T4LIT(${table.match_type}) "/" T4LIT(%d) ": %s",
        #[               ${table.key_length_bytes},
        #[               ${table.key_length_bytes} == 0 ? "$$[bytes]{}{(empty key)}" : "");

        #[     table_entry_${table.name}_t* entry = (table_entry_${table.name}_t*)${lookupfun[table.match_type]}(tables[TABLE_${table.name}], (uint8_t*)key);
        #[     bool hit = entry != NULL && entry->is_entry_valid != INVALID_TABLE_ENTRY;

        #[     debug("   " T4LIT(??,table) " Lookup $$[success]{}{%s}: $$[action]{}{%s}%s\n",
        #[               hit ? "hit" : "miss",
        #[               entry == NULL ? "(no action)" : action_names[entry->action.action_id],
        #[               hit ? "" : " (default)");

        #{     if (likely(hit)) {
        #[         // applying direct counters and meters
        for smem in table.direct_meters + table.direct_counters:
            for comp in smem.components:
                value = "pd->parsed_length" if comp['for'] == 'bytes' else "1"
                type = comp['type']
                name  = comp['name']
                #[ extern void apply_${smem.smem_type}(${smem.smem_type}_t*, int, const char*, const char*, const char*);
                #[ apply_${smem.smem_type}(&(global_smem.${name}_${table.name}), $value, "${table.name}", "${smem.smem_type}", "$name");
        #}    }
    else:
        action = table.default_action.expression.method.ref.name if hasattr(table, 'default_action') else None

        if action:
            #[    debug(" :::: Lookup on keyless table " T4LIT(${table.name},table) ", default action is " T4LIT($action,action) "\n");
            #[    table_entry_${table.name}_t resStruct = {
            #[        .action = { action_${table.default_action.expression.method.ref.name} },
            #[    };
            #[    table_entry_${table.name}_t* entry = &resStruct;
            #[    bool hit = true;
            #[    bool is_default = false;
        else:
            #[    debug(" :::: Lookup on keyless table " T4LIT(${table.name},table) ", " T4LIT(no default action,action) "\n");
            #[    table_entry_${table.name}_t* entry = (struct ${table.name}_action*)0;
            #[    bool hit = false;
            #[    bool is_default = false;


    # ACTIONS
    #[     if (likely(entry != 0)) {
    #{       switch (entry->action.action_id) {
    for action in table.actions:
        action_name = action.action_object.name
        if action_name == 'NoAction':
            continue
        #{         case action_${action_name}:
        #[           action_code_${action_name}(SHORT_STDPARAMS_IN, entry->action.${action_name}_params);
        #}           break;
    #[       }
    #}     }

    #[     struct apply_result_s apply_result = { hit, hit ? entry->action.action_id : -1 };
    #[     return apply_result;
    #} }


################################################################################

#{ void reset_headers(SHORT_STDPARAMS) {
for h in hlir16.header_instances:
    if not h.type('type_ref', lambda t: t.is_metadata):
        if "tmp" in h.id:
            #[ pd->headers[header_instance_ethernet].pointer = NULL;
        else:
            #[ pd->headers[${h.id}].pointer = NULL;

#[     // reset metadatas
#[     memset(pd->headers[header_instance_all_metadatas].pointer, 0, header_info(header_instance_all_metadatas).bytewidth * sizeof(uint8_t));
#[     memset(pd->headers[header_instance_meta].pointer, 0, header_info(header_instance_meta).bytewidth * sizeof(uint8_t));
#} }

#{ void init_headers(SHORT_STDPARAMS) {
for h in hlir16.header_instances:
    if not h.type('type_ref', lambda t: t.is_metadata):
        if "tmp" in h.id:
            #[ pd->headers[header_instance_ethernet] = (header_descriptor_t)
            #{ {
            #[     .type =  'header_instance_ethernet',
            #[     .length = header_info(header_instance_ethernet).bytewidth,
            #[     .pointer = NULL,
            #[     .var_width_field_bitwidth = 0,
            #} };
        else:
            #[ pd->headers[${h.id}] = (header_descriptor_t)
            #{ {
            #[     .type = ${h.id},
            #[     .length = header_info(${h.id}).bytewidth,
            #[     .pointer = NULL,
            #[     .var_width_field_bitwidth = 0,
            #} };

#[     // init metadatas
#[     pd->headers[header_instance_all_metadatas] = (header_descriptor_t)
#{     {
#[         .type = header_instance_all_metadatas,
#[         .length = header_info(header_instance_all_metadatas).bytewidth,
#[         .pointer = malloc(header_info(header_instance_all_metadatas).bytewidth * sizeof(uint8_t)),
#[         .var_width_field_bitwidth = 0
#}     };
#[     // init routing_metadatas
#[     pd->headers[header_instance_meta] = (header_descriptor_t)
#{     {
#[         .type = header_instance_meta,
#[         .length = header_info(header_instance_meta).bytewidth,
#[         .pointer = malloc(header_info(header_instance_meta).bytewidth * sizeof(uint8_t)),
#[         .var_width_field_bitwidth = 0
#}     };
#} }

################################################################################

def is_keyless_single_action_table(table):
    return table.key_length_bytes == 0 and len(table.actions) == 2 and table.actions[1].action_object.name.startswith('NoAction')

for table in hlir16.tables:
    if is_keyless_single_action_table(table):
        #[ extern void ${table.name}_setdefault(struct ${table.name}_action);

#{ void init_keyless_tables() {
for table in hlir16.tables:
    if is_keyless_single_action_table(table):
        action = table.actions[0].action_object
        #[ struct ${table.name}_action ${table.name}_a;
        #[ ${table.name}_a.action_id = action_${action.name};
        #[ ${table.name}_setdefault(${table.name}_a);
#} }

################################################################################

#{ void init_dataplane(SHORT_STDPARAMS) {
#[     init_headers(SHORT_STDPARAMS_IN);
#[     reset_headers(SHORT_STDPARAMS_IN);
#[     init_keyless_tables();

#[     uint32_t res32;
#[     MODIFY_INT32_INT32_BITS_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_drop, false);
#} }

#{ void update_packet(packet_descriptor_t* pd) {
#[     uint32_t value32, res32;
#[     (void)value32, (void)res32;
for hdr in hlir16.header_instances:
    if not hasattr(hdr.type, 'type_ref'):
        continue

    #[ 
    #[ // updating header instance ${hdr.name}

    for fld in hdr.type.type_ref.fields:
        if not fld.preparsed and fld.canonical_type().size <= 32:
            #{ if(pd->fields.attr_field_instance_${hdr.name}_${fld.name} == MODIFIED) {
            #[     value32 = pd->fields.field_instance_${hdr.name}_${fld.name};
            #[     MODIFY_INT32_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_instance_${hdr.name}_${fld.name}, value32);
            #[     // set_field((fldT[]){{pd, header_instance_${hdr.name}, field_${hdr.type.type_ref.name}_${fld.name}}}, 0, value32, ${fld.canonical_type().size});
            #} }
#} }

################################################################################
# Pipeline

class types:
    def __init__(self, new_type_env):
        global type_env
        self.env_vars = set()
        for v in new_type_env:
            if v in type_env:
                addWarning('adding a type environment', 'variable {} is already bound to type {}'.format(v, type_env[v]))
            else:
                self.env_vars.add(v)
                type_env[v] = new_type_env[v]

    def __enter__(self):
        global type_env
        return type_env

    def __exit__(self, type, value, traceback):
        global type_env
        for v in self.env_vars:
            del type_env[v]

# forward declarations for externs
for m in hlir16.objects['Method']:
    # TODO temporary fix for l3-routing-full, this will be computed later on
    with types({
        "T": "struct uint8_buffer_s",
        "O": "unsigned",
        "HashAlgorithm": "int",
        "D": "uint16_t",
        "M": "uint32_t",
        "P": "uint32_t*"
    }):
        t = m.type
        ret_type = format_type(t.returnType)
        args = ", ".join([format_expr(arg) for arg in t.parameters.parameters] + ['SHORT_STDPARAMS'])

        #[ extern ${ret_type} ${m.name}(${args});

for ctl in p4_ctls:
    #[ void control_${ctl.name}(STDPARAMS)
    #{ {
    #[     debug("Entering control $$[control]{ctl.name}...\n");
    #[     uint32_t value32, res32;
    #[     (void)value32, (void)res32;
    #[     control_locals_${ctl.name}_t local_vars_struct;
    #[     control_locals_${ctl.name}_t* local_vars = &local_vars_struct;
    #[     pd->control_locals = (void*) local_vars;
    #= format_statement(ctl.body, ctl)
    #} }

#[ void process_packet(STDPARAMS)
#{ {
it=0
for ctl in p4_ctls:
    #[ control_${ctl.name}(STDPARAMS_IN);
    if hlir16.p4_model == 'V1Switch' and it==1:
        #[ transfer_to_egress(pd);
    it = it+1;
    if ctl.name == 'egress':
        #[ // TODO temporarily disabled
        #[ // update_packet(pd); // we need to update the packet prior to calculating the new checksum
#} }

################################################################################

longest_hdr_name_len =max({len(h.name) for h in hlir16.header_instances if hasattr(h.type._type_ref, 'is_metadata') if not h.type._type_ref.is_metadata })

pkt_name_indent = " " * longest_hdr_name_len

#[ void store_headers_for_emit(STDPARAMS)
#{ {
#[     debug("   :: Preparing $${}{%d} header instances for storage...\n", pd->emit_hdrinst_count);

#[     pd->emit_headers_length = 0;
#{     for (int i = 0; i < pd->emit_hdrinst_count; ++i) {
#[         header_descriptor_t hdr = pd->headers[pd->header_reorder[i]];

#[
#{         #if PPK_EMIT != 1
#{             if (unlikely(hdr.pointer == NULL)) {
#[                 debug("        : " T4LIT(#%d) " $$[header][%]{longest_hdr_name_len}{s}/$${}{%02d} = " T4LIT(skipping invalid header,warning) "\n", pd->header_reorder[i] + 1, hdr.name, hdr.length);
#[                 continue;
#}             }
#}         #endif

#{         if (likely(hdr.was_enabled_at_initial_parse)) {
#[             dbg_bytes(hdr.pointer, hdr.length, "        : " T4LIT(#%d) " $$[header][%]{longest_hdr_name_len}{s}/$${}{%02d} = %s", pd->header_reorder[i] + 1, hdr.name, hdr.length, hdr.pointer == NULL ? T4LIT((invalid),warning) " " : "");
#[             memcpy(pd->header_tmp_storage + header_instance_infos[hdr.type].byte_offset, hdr.pointer, hdr.length);
#[         } else {
#[             debug("        : " T4LIT(#%d) " $$[header][%]{longest_hdr_name_len}{s}/$${}{%02d} was created in-place (not present at ingress)\n", pd->header_reorder[i] + 1, hdr.name, hdr.length);
#}         }
#[
#[         pd->emit_headers_length += hdr.length;
#}     }
#} }

#[ void resize_packet_on_emit(STDPARAMS)
#{ {
#[     pd->parsed_length -= 4;
#{     if (likely(pd->emit_headers_length == pd->parsed_length)) {
#[         debug(" " T4LIT(::::,status) " Skipping packet resizing: no change in total packet header length\n");
#[         return;
#}     }
#[
#{     if (likely(pd->emit_headers_length > pd->parsed_length)) {
#[         int len_change = pd->emit_headers_length - pd->parsed_length;
#[         debug("   " T4LIT(::,status) " Adding   $${}{%02d} bytes %${longest_hdr_name_len}{s}   : (header: from $${}{%d} bytes to $${}{%d} bytes)\n", len_change, "to packet", pd->parsed_length, pd->emit_headers_length);
#[         char* new_ptr = rte_pktmbuf_prepend(pd->wrapper, len_change);
#[         if (unlikely(new_ptr == 0)) {
#[             rte_exit(1, "Could not reserve necessary headroom ($${}{%d} additional bytes)", len_change);
#[         }
#[         pd->data = (packet_data_t*)new_ptr;
#[     } else {
#[         int len_change = pd->parsed_length - pd->emit_headers_length;
#[         debug("   " T4LIT(::,status) " Removing $${}{%02d} bytes %${longest_hdr_name_len}{s}  : (header: from $${}{%d} bytes to $${}{%d} bytes)\n", len_change, "from packet", pd->parsed_length, pd->emit_headers_length);
#[         char* new_ptr = rte_pktmbuf_adj(pd->wrapper, len_change);
#[         pd->data = (packet_data_t*)new_ptr;
#}     }
#[     pd->wrapper->pkt_len = pd->emit_headers_length + pd->payload_length + 4;
#} }

#[ // if (some of) the emitted headers are one after another, this function copies them in one go
#[ void copy_emit_contents(STDPARAMS)
#{ {
#[     debug("   :: Putting together packet\n");
#[     uint8_t* dst_start = rte_pktmbuf_mtod(pd->wrapper, uint8_t*);
#[     uint8_t* dst = dst_start;
#[     //TODO by IAN
#[       struct vlan_tag
#[    {  
#[         uint16_t type;
#[         uint16_t vid:12;
#[         uint8_t cfi:1;
#[         uint8_t pri:3;
#[     }vlan;
#{     for (int idx = 0; idx < pd->emit_hdrinst_count; ) {
#[             if (pd->headers[pd->header_reorder[idx]].pointer == NULL){
#[             idx++;
#[             continue;
#[         }
#[            int egress_port = extract_egress_port(pd);

#[         #ifdef PPK_DEBUG
#[             char header_names_txt[1024];
#[             char* header_names_ptr = header_names_txt;
#[         #endif
#[         header_descriptor_t hdr = pd->headers[pd->header_reorder[idx]];
#[         uint8_t* copy_start     = hdr.pointer;
#[         int copy_start_idx      = idx;
#[         int copy_length         = hdr.length;
#[         int count               = 1;
#[         #ifdef PPK_DEBUG
#[             header_names_ptr += sprintf(header_names_ptr, " " T4LIT(%s,header), hdr.name);
#[         #endif
#[         ++idx;
#{         while (idx < pd->emit_hdrinst_count && pd->headers[pd->header_reorder[idx]].pointer == hdr.pointer + hdr.length) {
#[             ++count;
#[             hdr = pd->headers[pd->header_reorder[idx]];
#[             copy_length += hdr.length;
#[             ++idx;
#[             #ifdef PPK_DEBUG
#[                 header_names_ptr += sprintf(header_names_ptr, " " T4LIT(%s,header), hdr.name);
#[             #endif
#}         }
#[         dbg_bytes(copy_start, copy_length, "    : Copying " T4LIT(%d) " %s to byte " T4LIT(#%ld) " of egress header, " T4LIT(%d) " bytes: %s: ", count, count == 1 ? "header" : "adjacent headers", dst - dst_start, copy_length, header_names_txt);
#[         memcpy(dst, copy_start, copy_length);
#[         dst += copy_length;
#}     }
#} }

#[ void emit_packet(STDPARAMS)
#{ {
#[     if (unlikely(pd->is_emit_reordering)) {
#{         if (unlikely(GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_standard_metadata_t_drop))) {
#[             debug(" " T4LIT(::::,status) " Skipping pre-emit processing: packet is " T4LIT(dropped,status) "\n");
#[             return;
#}         }
#[         debug(" :::: Pre-emit reordering\n");
#[         store_headers_for_emit(STDPARAMS_IN);
#[         resize_packet_on_emit(STDPARAMS_IN);
#[         copy_emit_contents(STDPARAMS_IN);
#[     } else {
#[         debug(" " T4LIT(::::,status) " Skipping pre-emit processing: no change in packet header structure\n");
#[     }
#} }

#[ void handle_packet(STDPARAMS, uint32_t portid)
#{ {
#[     int value32;
#[     int res32;
#[
#[     reset_headers(SHORT_STDPARAMS_IN);
#[     set_handle_packet_metadata(pd, portid);
#[
#[     dbg_bytes(pd->data, packet_length(pd), "Handling packet (port " T4LIT(%d,port) ", $${}{%02d} bytes)  : ", extract_ingress_port(pd), packet_length(pd));
#[
#[     pd->parsed_length = 0;
#[     parse_packet(STDPARAMS_IN);
#[
#[     emit_addr = pd->data;
#[     pd->emit_hdrinst_count = 0;
#[     pd->is_emit_reordering = false;
#[
#[     process_packet(STDPARAMS_IN);
#[
#[     emit_packet(STDPARAMS_IN);
#} }
