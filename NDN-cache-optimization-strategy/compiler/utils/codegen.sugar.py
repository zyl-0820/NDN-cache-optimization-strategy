# Copyright 2017 Eotvos Lorand University, Budapest, Hungary
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

from utils.misc import addWarning, addError
import re
################################################################################

SHORT_STDPARAMS = "packet_descriptor_t* pd, lookup_table_t** tables"
SHORT_STDPARAMS_IN = "pd, tables"
STDPARAMS = SHORT_STDPARAMS + ", parser_state_t* pstate"
STDPARAMS_IN = SHORT_STDPARAMS_IN + ", pstate"

################################################################################

type_env = {}

def gen_format_type(t, resolve_names = True, use_array = False, addon = ""):
    """Returns a type. If the type has a part that has to come after the variable name in a declaration,
    such as [20] in uint8_t varname[20], it should be separated with a space."""
    if t.node_type == 'Type_Specialized':
        extern_name = t.baseType.path.name

        # TODO is there a more straightforward way to deal with such externs?
        argtyped_externs = ["Digest"]

        if extern_name in argtyped_externs:
            #[ ${t.arguments[0].type_ref.name}
        else:
            param_count = len(t.baseType.type_ref.typeParameters.parameters)
            if param_count != 1:
                addError('formatting type', 'Type {} has {} parameters; only 1 parameter is supported'.format(t.name, param_count))

            type_name = gen_format_type(t.arguments[0]._type_ref, resolve_names)
            #[ ${extern_name}_${type_name}
    elif t.node_type == 'Type_Void':
        #[ void
    elif t.node_type == 'Type_Boolean':
        #[ bool
    elif t.node_type == 'Type_Bits':
        res = 'int' if t.isSigned else 'uint'
        if t.size <= 8:
            res += '8_t'
        elif t.size <= 16:
            res += '16_t'
        elif t.size <= 32:
            res += '32_t'
        elif use_array:
            res += '8_t [{}]'.format((t.size+7)/8)
        else:
            res += '8_t*'
        return res
    elif t.node_type == 'Type_Name':
        if t.type_ref.node_type in {'Type_Enum', 'Type_Error'}:
            #[ enum ${t.type_ref.c_name}
        else:
            if not resolve_names:
                return t.type_ref.name

            global type_env

            if t.type_ref.name in type_env:
                return type_env[t.type_ref.name]
            if t.type_ref.name=="P":
                #[ uint32_t*
            else:    
                #[ ${t.type_ref.name}
    elif t.node_type == 'Type_Extern':
        #[ ${t.name}_t
    elif t.node_type == 'Type_Struct':
        struct_name = "{}_s".format(t.name[:-2]) if t.name.endswith("_t") else t.name
        #[ struct ${struct_name}
    elif t.node_type == 'Type_Varbits':
        #[ uint8_t [${(t.size+7)/8}] /* preliminary type for varbits */
    elif t.node_type == 'Type_Var':
        #[ void
    else:
        addError('formatting type', 'Type {} for node ({}) is not supported yet!'.format(t.node_type, t))
        #[ int /* generated in place of unknown type ${t.node_type} */

def pp_type_16(t):
    """Pretty print P4_16 type"""
    if t.node_type == 'Type_Boolean':
        return 'bool'
    elif t.node_type == 'Type_Bits':
        return ('int' if t.isSigned else 'bit') + '<' + str(t.size) + '>'
    else:
        return str(t)

def gen_format_type_mask(t):
    if t.node_type == 'Type_Bits' and not t.isSigned:
        mask = hex((2 ** t.size) - 1)
        #[ $mask&
    else:
        addError('formatting a type mask', 'Currently only bit<w> is supported!')

def method_parameters_by_type(args, method_params):
    for (par, tpar) in zip(args, method_params.parameters):
        if tpar('type.type_ref.is_metadata', False):
            continue

        yield (par, tpar.type)

def format_method_parameter(par):
    if hasattr(par, 'field_ref'):
        return 'handle(header_desc_ins(pd, {}), {})'.format(par.expr.header_ref.id, par.expression.field_ref.id)
    else:
        # return format_expr(par)[0:m.expr.path.name.rfind("_")]
        return format_expr(par.expression,expand_parameters=True)

def gen_format_method_parameters(args, method_params):
    c = []
    for (par, tpar) in method_parameters_by_type(args, method_params):
        if hasattr(par.expression, 'field_ref'):
            name = "field_metadata_"+par.expression.field_ref.name
            c += [name]
        else:
            c += [format_method_parameter(par)]
    return ', '.join(c)
    #return ', '.join([format_method_parameter(par) for (par, tpar) in method_parameters_by_type(args, method_params)])

def gen_format_declaration(d, varname_override):
    var_name = d.name if varname_override is None else varname_override

    if d.node_type == 'Declaration_Variable':
        if d.type('type_ref.node_type', 'not header') == 'Type_Header':
            # Data for variable width headers is stored in parser_state_t
            pass
        elif d.type.node_type == 'Type_Boolean':
            #[ bool ${var_name} = false;
        else:
            t = gen_format_type(d.type, False)
            #[ $t ${var_name};
    elif d.node_type == 'Declaration_Instance':
        t = gen_format_type(d.type, False) + "_t"
        #[ extern void ${t}_init(${t}*);
        #[ $t ${var_name};
        #[ ${t}_init(&${var_name});
    elif d.node_type in ['P4Table', 'P4Action']:
        #[ /* nothing */
    else:
        addError('formatting declaration', 'Declaration of type %s is not supported yet!' % d.node_type)

################################################################################

def is_metadata(e):
    if e.node_type == 'Member':
        if hasattr(e.expr, 'header_ref'):
            return e.expr.header_ref.type.type_ref.is_metadata
        elif hasattr(e.expr.type, 'is_metadata'):
            return e.expr.type.is_metadata
        else:
            return False
    return False


def is_std_metadata(e):
    return is_metadata(e) and e.expr.type.name == 'standard_metadata_t'

################################################################################

enclosing_control = None

pre_statement_buffer = ""
post_statement_buffer = ""

def prepend_statement(s):
    global pre_statement_buffer
    pre_statement_buffer += "\n" + s

def append_statement(s):
    global post_statement_buffer
    post_statement_buffer += s + "\n"

def statement_buffer_value():
    global pre_statement_buffer
    global post_statement_buffer
    ret = (pre_statement_buffer, post_statement_buffer)
    pre_statement_buffer = ""
    post_statement_buffer = ""
    return ret


def is_control_local_var(var_name):
    global enclosing_control

    def get_locals(node):
        if node.node_type == 'P4Parser':  return node.parserLocals
        if node.node_type == 'P4Control': return node.controlLocals
        return []

    return enclosing_control is not None and [] != [cl for cl in get_locals(enclosing_control) if cl.name == var_name]


var_name_counter = 0
generated_var_names = set()

def generate_var_name(var_name_part = "var", var_id = None):
    global var_name_counter
    global generated_var_names

    var_name_counter += 1

    var_name = var_name_part + "_" + str(var_name_counter)
    if var_id is not None:
        simpler_var_name = var_name_part + "_" + var_id
        if simpler_var_name not in generated_var_names:
            var_name = simpler_var_name
        else:
            var_name = simpler_var_name + "_" + str(var_name_counter)

    generated_var_names.add(var_name)

    return var_name

################################################################################

def int_to_big_endian_byte_array_with_length(value, width, base=10):
    array = []
    while value > 0:
        array.append(int(value % 256))
        value /= 256
    array.reverse()
    array_len = len(array)
    padded_array = [0 for i in range(width-array_len)] + array[array_len-min(array_len, width) : array_len]
    return '{' + ', '.join([print_with_base(x, base) for x in padded_array]) + '}'


def bit_bounding_unit(t):
    """The bit width of the smallest int that can contain the type,
    or the string "bytebuf" if it is larger than all possible container types."""
    if t.size <= 8:
        return "8"
    if t.size <= 16:
        return "16"
    if t.size <= 32:
        return "32"
    return "bytebuf"

def gen_extern_format_parameter(expr, par, packets_or_bytes_override = None):
    def member_to_field_id(member):
        return 'field_{}_{}'.format(member.expr.type.name, member.member)

    # TODO
    # if packets_or_bytes_override:
    if par.direction == "in" or expr.node_type != "Member":
        prefix = "&" if par.direction != "in" and par.type.node_type != 'Type_Bits' else ""
        #[ $prefix(${format_expr(expr, format_as_value=True, expand_parameters=True)})
    else:
        expr_width = expr.type.size;

        member = "all_metadatas" if expr.expr.ref.type.type_ref.is_metadata else expr.expr.member if hasattr(expr.expr, 'member') else expr.member

        if expr_width<=32:
            expr_unit = bit_bounding_unit(expr.type)
            #pre[ uint${expr_unit}_t value_${expr.id};
            if par.direction=="inout":
                #pre[ value_${expr.id} = ${format_expr(expr)};
            #aft[ set_field((fldT[]){{pd, header_instance_$member, ${member_to_field_id(expr)} }}, 0, value_${expr.id}, ${expr_width});
            #[ &value_${expr.id}
        else:
            #pre[ uint8_t value_${expr.id}[${(int)((expr_width+7)/8)}];
            if par.direction=="inout":
                #pre[ EXTRACT_BYTEBUF_PACKET(pd, header_instance_${member}, ${member_to_field_id(expr)}, value_${expr.id});
            #aft[ MODIFY_BYTEBUF_BYTEBUF_PACKET(pd, header_instance_${member}, ${member_to_field_id(expr)}, value_${expr.id}, ${expr_width});
            #[ value_${expr.id}




def member_to_field_id(member):
    return 'field_{}_{}'.format(member.expr.type.name, member.member)

def gen_format_statement_fieldref_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_header_id, dst_field_id):
    if src.node_type == 'Member':
        src_pointer = 'tmp_fldref_{}'.format(src.id)
        #[ uint8_t $src_pointer[$dst_bytewidth];

        if hasattr(src, 'field_ref'):
            hdrinst = 'all_metadatas' if src.expr.type.is_metadata else src.expr.member
            #[ EXTRACT_BYTEBUF_PACKET(pd, header_instance_${hdrinst}, ${member_to_field_id(src)}, ${src_pointer})
            if dst_is_vw:
                src_vw_bitwidth = 'pd->headers[header_instance_{}].var_width_field_bitwidth'.format(src.expr.member)
                dst_bytewidth = '({}/8)'.format(src_vw_bitwidth)
        else:
            srcname = src.expr.ref.name
            #[ EXTRACT_BYTEBUF_BUFFER(pstate->${srcname}, pstate->${srcname}_var, ${member_to_field_id(src)}, $src_pointer)
            if dst_is_vw:
                src_vw_bitwidth = 'pstate->{}_var'.format(src.expr.ref.name)
                dst_bytewidth = '({}/8)'.format(src_vw_bitwidth)
    elif src.node_type == 'PathExpression':
        refbase = "local_vars->" if is_control_local_var(src.ref.name) else 'parameters.'
        src_pointer = '{}{}'.format(refbase, src.ref.name)
    elif src.node_type == 'Constant':
        src_pointer = 'tmp_fldref_{}'.format(src.id)
        #[ uint8_t $src_pointer[$dst_bytewidth] = ${int_to_big_endian_byte_array_with_length(src.value, dst_bytewidth, src.base)};
    elif src.node_type == 'Mux':
        src_pointer = 'tmp_fldref_{}'.format(src.id)
        #[ uint8_t $src_pointer[$dst_bytewidth] = ((${format_expr(src.e0.left)}) == (${format_expr(src.e0.right)})) ? (${format_expr(src.e1)}) : (${format_expr(src.e2)});
    else:
        src_pointer = 'NOT_SUPPORTED'
        addError('formatting statement', 'Assignment to unsupported field in: {} = {}'.format(format_expr(dst), src))
    dst_fixed_size = dst.expr.header_ref.type.type_ref.bit_width - dst.field_ref.size

    if dst_is_vw:
        #[ pd->headers[$dst_header_id].var_width_field_bitwidth = get_var_width_bitwidth(pstate);
        #[ pd->headers[$dst_header_id].length = ($dst_fixed_size + pd->headers[$dst_header_id].var_width_field_bitwidth)/8;

    #[ MODIFY_BYTEBUF_BYTEBUF_PACKET(pd, $dst_header_id, $dst_field_id, $src_pointer, $dst_bytewidth)

    #[ dbg_bytes($src_pointer, $dst_bytewidth,
    #[      "    " T4LIT(=,field) " Modifying field " T4LIT(%s,header) "." T4LIT(%s,field) "/" T4LIT(%d) "b (" T4LIT(%d) "B) = ",
    #[      header_instance_names[$dst_header_id],
    #[      field_names[$dst_field_id], // $dst_field_id
    #[      $dst_bytewidth*8,
    #[      $dst_bytewidth
    #[      );

    #[ dbg_bytes(pd->headers[$dst_header_id].pointer + (160/8), $dst_bytewidth,
    #[      "    " T4LIT(=,field) " Modifying field " T4LIT(%s,header) "." T4LIT(%s,field) "/" T4LIT(%d) "b (" T4LIT(%d) "B) = ",
    #[      header_instance_names[$dst_header_id],
    #[      field_names[$dst_field_id], // $dst_field_id
    #[      $dst_bytewidth*8,
    #[      $dst_bytewidth
    #[      );

def is_primitive(typenode):
    """Returns true if the argument node is compiled to a non-reference C type."""
    # TODO determine better if the source is a reference or not
    return typenode.node_type in ["Type_Boolean"] or (typenode.node_type == 'Type_Bits' and typenode.size <= 32)


def gen_format_statement_fieldref_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_header_id, dst_field_id):
    src_buffer = 'value32'
    if src.node_type == 'Member':
        #[ $src_buffer = ${format_expr(src)};
    elif src.node_type == 'PathExpression':
        indirection = "&" if is_primitive(src.type) else ""
        refbase = "local_vars->" if is_control_local_var(src.ref.name) else 'parameters.'
        #[ memcpy(&$src_buffer, $indirection($refbase${src.ref.name}), $dst_bytewidth);
    else:
        #[ $src_buffer = ${format_expr(src)};


    #[ // MODIFY_INT32_INT32_AUTO_PACKET(pd, $dst_header_id, $dst_field_id, $src_buffer)
    #[ set_field((fldT[]){{pd, $dst_header_id, $dst_field_id}}, 0, $src_buffer, $dst_width);


def gen_format_statement_fieldref(dst, src):
    #TODO: handle preparsed fields, width assignment for vw fields and assignment to buffer instead header fields
    dst_width = dst.type.size
    dst_is_vw = dst.type.node_type == 'Type_Varbits'
    dst_bytewidth = (dst_width+7)/8

    assert(dst_width == src.type.size)
    assert(dst_is_vw == (src.type.node_type == 'Type_Varbits'))

    dst_name      = dst.expr.member if dst.expr.node_type == 'Member' else dst.expr.path.name if dst.expr('header_ref', lambda h: h.type_ref.is_metadata) else dst.expr._header_ref._path.name
    if dst.expr("ref.type.type_ref.is_metadata") and dst.expr.path.name == "meta":
        dst_header_id = "header_instance_meta"
    elif dst.expr("ref.type.type_ref.is_metadata"):
        dst_header_id = "header_instance_all_metadatas"
    else:
        dst_header_id = 'header_instance_{}'.format(dst_name)
    #dst_header_id = "header_instance_all_metadatas" if dst.expr("ref.type.type_ref.is_metadata") else 'header_instance_{}'.format(dst_name)
    dst_field_id  = member_to_field_id(dst)

    if dst_width <= 32:
        #= gen_format_statement_fieldref_short(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_header_id, dst_field_id)
    else:
        #= gen_format_statement_fieldref_wide(dst, src, dst_width, dst_is_vw, dst_bytewidth, dst_name, dst_header_id, dst_field_id)



def is_atomic_block(blckstmt):
    try:
        for annot in blckstmt.annotations.annotations.vec:
            if annot.name == "atomic":
               return True
    except:
        return False
    return False


def gen_do_assignment(dst, src):
    if dst.type.node_type == 'Type_Header':
        #[ // TODO make it work properly for non-byte-aligned headers
        if hasattr(dst, "member"):
            if hasattr(src, "member"):
                #[ memcpy(pd->headers[header_instance_${dst.member}].pointer, pd->headers[header_instance_${src.member}].pointer, header_instance_byte_width[header_instance_${src.member}]);
                #[ dbg_bytes(pd->headers[header_instance_${dst.member}].pointer, header_instance_byte_width[header_instance_${src.member}], "Copied %02d bytes from header_instance_${src.member} to header_instance_${dst.member}: ", header_instance_byte_width[header_instance_${src.member}]);
            else:
                addError("Compiling assignment", "Assigning to header instance {} (type {}) from {} ({}) is not supported".format(dst.member, dst.type.name, src.ref.name, src.type.name))
        else:
            addError("Compiling assignment", "Assigning {} (type {}) from {} ({}) is not supported".format(dst.ref.name, dst.type.name, src.ref.name, src.type.name))
    elif dst.type.node_type == 'Type_Bits':
        # TODO refine the condition to find out whether to use an assignment or memcpy
        requires_memcpy = src.type.size > 32
        is_assignable = src.type.size in range(0,17)

        if src.type.node_type == 'Type_Bits' and not requires_memcpy:
            if is_assignable:
                # TODO how to decide whether src is a pointer, and therefore needs dereferencing?
                needs_defererencing = src.node_type not in ["Constant"]
                # needs_defererencing = src('field_ref', lambda fr: fr.name == 'meta')
                dereference = "*" if needs_defererencing else ""

                if dst("expr.ref.type.type_ref.is_metadata"):
                    #[ set_field((fldT[]){{pd, header_instance_all_metadatas, field_${dst.expr.ref.type.type_ref.name}_${dst.member}}}, 0, ($dereference(${format_expr(src, expand_parameters=True)})), ${dst.type._type_ref.size});
                    #[ debug("       : " T4LIT(all_metadatas,header) "." T4LIT(${dst.expr.ref.type.type_ref.name}_${dst.member},field) "/" T4LIT(%d) " = " T4LIT(%d,bytes) " (" T4LIT(%${(src.type.size+7)/8}x,bytes) ")\n", ${dst.type._type_ref.size}, $dereference(${format_expr(src, expand_parameters=True)}), $dereference(${format_expr(src, expand_parameters=True)}));
                elif dst("header_ref.type.type_ref.is_metadata"):
                    #[ set_field((fldT[]){{pd, header_instance_all_metadatas, field_${dst.header_ref.type.type_ref.name}_${dst.field_name}}}, 0, ($dereference(${format_expr(src, expand_parameters=True)})), ${dst.type._type_ref.size});
                    #[ debug("       : " T4LIT(all_metadatas,header) "." T4LIT(${dst.header_ref.type.type_ref.name}_${dst.field_name},field) "/" T4LIT(%d) " = " T4LIT(%d,bytes) " (" T4LIT(%${(src.type.size+7)/8}x,bytes) ")\n", ${dst.type._type_ref.size}, $dereference(${format_expr(src, expand_parameters=True)}), $dereference(${format_expr(src, expand_parameters=True)}));
                else:
                    if hasattr(src,'method'):
                        if src.method.member == "lookahead":
                            #[ ${format_expr(dst)} = ${format_expr(src, expand_parameters=True)};
                        else:
                            #[ ${format_expr(dst)} = (${format_type(dst.type)})((${format_expr(src, expand_parameters=True)}));
                    if dst.node_type == 'Member':
                        if dst.type('is_metadata', lambda ismeta: ismeta):
                            # Note: the metadata header and field name is joined by underscores, separating them as best as possible
                            nameparts = dst.member.split("_")
                            hdr = "_".join(nameparts[1:-1])
                            fld = nameparts[-1]
                        else:
                            hdr = dst.expr.path.name
                            fld = dst.member
                        #[ debug("       : " T4LIT($hdr,header) "." T4LIT($fld,field) " = " T4LIT(%d,bytes) " (" T4LIT(%${(src.type.size+7)/8}x,bytes) ")\n", ${format_expr(dst)}, ${format_expr(dst)});
                    else:
                        #[ debug("       : " T4LIT(${format_expr(dst, expand_parameters=True)},header) " = " T4LIT(%d,bytes) " (" T4LIT(%${(src.type.size+7)/8}x,bytes) ")\n", ${format_expr(dst)}, ${format_expr(dst)});
            else:
                tmpvar = generate_var_name()
                #[ ${format_type(dst.type)} $tmpvar = ${format_expr(src, expand_parameters=True)};
                #[ ${format_expr(dst)} = $tmpvar;
                #[ ${format_expr(dst)} = (${format_type(dst.type)})((${format_expr(src, expand_parameters=True)}));
                # TODO this part should not require memcpy
                # [ ${format_type(dst.type)} $tmpvar = ${format_expr(src, expand_parameters=True)};
                # [ memcpy(&(${format_expr(dst)}), &$tmpvar, sizeof(${format_type(dst.type)}));
                # TODO debug printout
        else:
            #[ memcpy(&(${format_expr(dst)}), &(${format_expr(src, expand_parameters=True)}), ${dst.type.size});
            #[ dbg_bytes(&(${format_expr(src, expand_parameters=True)}), ${dst.type.size}, "Copied " T4LIT(%02d) " bytes from ${format_expr(src, expand_parameters=True)} to ${format_expr(dst)}: ", ${dst.type.size});
    else:
        #[ ${format_expr(dst)} = ${format_expr(src, expand_parameters=True)};


def gen_format_statement(stmt):
    global enclosing_control
    if stmt.node_type == 'AssignmentStatement':
        dst = stmt.left
        src = stmt.right
        if hasattr(dst, 'field_ref'):
            #= gen_format_statement_fieldref(dst, src)
        else:
            #= gen_do_assignment(dst, src)
    elif stmt.node_type == 'BlockStatement':
        is_atomic = is_atomic_block(stmt)
        if is_atomic:
            #[ LOCK(&${enclosing_control.type.name}_lock)
        for c in stmt.components:
            #= gen_format_statement(c)
        if is_atomic:
            #[ UNLOCK(&${enclosing_control.type.name}_lock)
    elif stmt.node_type == 'IfStatement':
        t = format_statement(stmt.ifTrue) if hasattr(stmt, 'ifTrue') else ';'
        f = format_statement(stmt.ifFalse) if hasattr(stmt, 'ifFalse') else ';'
        cond = format_expr(stmt.condition)

        # TODO this happens when .hit() is called; make a proper solution
        if cond.strip() == '':
            cond = "true"

        #{ if( $cond ) {
        #[     $t
        #}
        #{ } else {
        #[     $f
        #} }
    elif stmt.node_type == 'MethodCallStatement':
        m = stmt.methodCall.method

        if m.node_type == 'Method' and m.name == 'digest':
            return gen_format_methodcall_digest(stmt, m)
        else:
            if m.get_attr('member') is not None:
                return gen_format_expr_methodcall(stmt, m)
            else:
                #= gen_methodcall(stmt)
    elif stmt.node_type == 'SwitchStatement':
        #[ switch(${format_expr(stmt.expression)}) {
        for case in stmt.cases:
            if case.label.node_type == "DefaultExpression":
                #[ default:
            else:
                #[ case ${format_expr(case.label)}:
            #[   ${format_statement(case.statement)}
            #[   break;
        if [case for case in stmt.cases if case.label.node_type == "DefaultExpression"] == []:
            #[   default: {}
        #[ }

def gen_format_methodcall_digest(stmt, m):
    digest_name = stmt.methodCall.typeArguments[0].name
    port, fields = stmt.methodCall.arguments

    #[ struct type_field_list fields;
    #[ fields.fields_quantity = ${len(fields)};
    #[ fields.field_offsets = malloc(sizeof(uint8_t*)*fields.fields_quantity);
    #[ fields.field_widths = malloc(sizeof(uint8_t*)*fields.fields_quantity);

    for idx, f in enumerate(fields.components):
        if f.expr.type.is_metadata:
            #[ fields.field_offsets[$idx] = (uint8_t*) field_desc(pd, field_instance_${f.expr.name}_${f.member}).byte_addr;
            #[ fields.field_widths[$idx]  =            field_desc(pd, field_instance_${f.expr.name}_${f.member}).bitwidth;
        else:
            #[ fields.field_offsets[$idx] = (uint8_t*) field_desc(pd, field_instance_${f.expr.member}_${f.expression.field_ref.name}).byte_addr;
            #[ fields.field_widths[$idx]  =            field_desc(pd, field_instance_${f.expr.member}_${f.expression.field_ref.name}).bitwidth;
    #[ generate_digest(bg,"${digest_name}",0,&fields);
    #[ sleep_millis(DIGEST_SLEEP_MILLIS);

def is_emit(stmt, m):
    return m.expr._ref('type')._type_ref('name', lambda n: n == 'packet_out')

def gen_format_expr_methodcall(stmt, m):
    if is_emit(stmt, m):
        arg = stmt.methodCall.arguments[0]
        hdr = arg.expression.member
        hdr_type = arg.expression.type

        hdr_name = arg.expression.header_ref.name if hasattr(arg.expression, 'header_ref') else arg.expression.member

        #[ pd->header_reorder[pd->emit_hdrinst_count] = header_instance_$hdr;
        #[ ++pd->emit_hdrinst_count;
    elif (m.expr.node_type, m.expr('ref').node_type, m.member) == ('PathExpression', 'P4Table', 'apply'):
        #[ ${gen_method_apply(stmt.methodCall)};
    elif m.expr.get_attr('member') is None:
        return gen_format_expr_methodcall_extern(stmt, m)
    else:
        hdr_name = m.expr.member

        if m.member == 'isValid':
            #[ controlLocal_tmp_0 = (pd->headers[header_instance_$hdr_name].pointer != NULL);
        elif m.member == 'setValid':
            #{ if (likely(pd->headers[header_instance_$hdr_name].pointer == NULL)) {
            #[    pd->headers[header_instance_$hdr_name].pointer = (pd->header_tmp_storage + header_instance_infos[header_instance_$hdr_name].byte_offset);
            #[    pd->is_emit_reordering = true;
            #[    debug("   :: Header instance $$[header]{hdr_name}/" T4LIT(%d) "B set as $$[success]{}{valid}\n", pd->headers[header_instance_$hdr_name].length);
            #[ } else {
            #[    debug("   " T4LIT(!!,warning) " Trying to set header instance $$[header]{hdr_name} to $$[success]{}{valid}, but it is already $$[success]{}{valid}\n");
            #} }
        elif m.member == 'setInvalid':
            #{ if (likely(pd->headers[header_instance_$hdr_name].pointer != NULL)) {
            #[    pd->headers[header_instance_$hdr_name].pointer = NULL;
            #[    pd->is_emit_reordering = true;
            #[    debug("   :: Header instance $$[header]{hdr_name}/" T4LIT(%d) "B set as $$[status]{}{invalid}\n", pd->headers[header_instance_$hdr_name].length);
            #[ } else {
            #[    debug("   " T4LIT(!!,warning) " Trying to set header instance $$[header]{hdr_name} to $$[success]{}{valid}, but it is already $$[success]{}{valid}\n");
            #} }
        else:
            #= gen_methodcall(stmt)

def gen_format_expr_methodcall_extern(stmt, m):
    smem_type = m.expr.type._baseType.name

    # if the extern is about both packets and bytes, it takes two separate calls
    is_possibly_multiple = smem_type in ["counter", "meter", "direct_counter", "direct_meter"]
    if is_possibly_multiple:
        if m.expr.ref.packets_or_bytes == "packets_and_bytes":
            #= gen_format_extern_single(stmt, m, smem_type, is_possibly_multiple, "packets")
            #= gen_format_extern_single(stmt, m, smem_type, is_possibly_multiple, "bytes")
        else:
            #= gen_format_extern_single(stmt, m, smem_type, is_possibly_multiple, m.expr.ref.packets_or_bytes)
    else:
        #= gen_format_extern_single(stmt, m, smem_type, is_possibly_multiple)


def gen_format_extern_single(stmt, m, smem_type, is_possibly_multiple, packets_or_bytes = None):
    mexpr_type = m.expr.type

    if m.expr.type.node_type == "Type_SpecializedCanonical":
        mexpr_type = mexpr_type.substituted
    parameters = stmt.methodCall.method.type.parameters.parameters
    method_args = zip(stmt.methodCall.arguments, parameters)
    mprefix = "global_smem."
    mname = mprefix + m.expr.path.name
    mparname = mname

    if smem_type in ["counter", "meter"]:
        mname = "{}{}_{}_{}".format(mprefix, smem_type, m.expr.path.name, packets_or_bytes)
        mparname = mname
    if smem_type in ["direct_counter", "direct_meter"]:
        mname = "{}{}_{}_{}_{}".format(mprefix, smem_type, m.expr.path.name, packets_or_bytes, "TODO_table")
        mparname = mname
    packets_or_bytes_override = None
    if method_args != []:
        (expr, par) = method_args[0]
        if m.expr.ref._packets_or_bytes == "packets_and_bytes":
            packets_or_bytes_override = packets_or_bytes
    if m.expr.type.node_type == "Type_Extern":
        # TODO support parameters of type Type_List (e.g. in InternetChecksum in the example psa-l3fwd-with-chksm)
        stypename = stmt.methodCall.method.expr.type.name
        paramtypes = ['{}_t*'.format(stypename) if idx == 0 else gen_format_type(arg[0].expression.type) for idx, arg in enumerate(method_args)]
    elif m.expr.type.node_type == "Type_SpecializedCanonical":
        method_args = method_args[1:]

        if hasattr(expr.expression, 'name'):
            paramtype = "struct " + expr.expression.name
        elif expr.expression.type.node_type == 'Type_Bits':
            paramtype = format_type(expr.expression.type)
        elif expr.expression.node_type == 'Constant':
            paramtype = format_type(expr.expression.type)
        elif m.expr.ref.type.baseType.type_ref.node_type == 'Type_Extern':
            paramtype = m.expr.type.arguments[0].name
        else:
            paramtype = "int/*temporarily inserted for unknown type*/"
            addWarning('generating method call statement', 'Unexpected type {} in {}'.format(m.expr.type, stmt.methodCall))

        if is_possibly_multiple and hasattr(expr.expression.type, 'fields'):
            tmpvar = generate_var_name()
            #[ $paramtype $tmpvar = ${gen_extern_format_parameter(expr, par, packets_or_bytes_override)};

            for fld, component in zip(expr.expression.type.fields, stmt.methodCall.arguments[0].expression.components):
                ce = component.expression

                if fld.type.size <= 32:
                    #[ dbg_bytes(&($tmpvar.${fld.name}), (${fld.type.size}+7)/8, "       : " T4LIT(${format_expr(ce.expr)},header) "." T4LIT(${ce.member},field) " = ");
                    continue

                hdr = ce.expr.header_ref.name

                #[ EXTRACT_BYTEBUF_PACKET(pd, header_instance_$hdr, field_instance_${hdr}_${ce.field_ref.name}, &($tmpvar.${fld.name}));
                #[ dbg_bytes(&($tmpvar.${fld.name}), (${fld.type.size}+7)/8, "       : " T4LIT(${hdr},header) "." T4LIT(${ce.field_ref.name},field) " = ");

            #[ memcpy(&($mname), &$tmpvar, sizeof($paramtype));
        paramtypes = [paramtype]
    def resolve_type(t, type_params):
        return type_params[t.name] if t.node_type == 'Type_Var' else t

    extern_param_indexes = {
        ('meter',        'execute_meter'): ([1]),
        ('register',     'read'):          ([0]),
        ('register',     'write'):         ([1]),
        ('Digest',       'pack'):          ([0]),
    }

    base_type = m.expr.ref.type
    if hasattr(base_type, 'baseType'):
        base_type = base_type.baseType

    extern_type = base_type.type_ref.name

    type_param_names = [t.name for t in stmt.methodCall.method.type.typeParameters.parameters]
    type_params = dict(zip(type_param_names, stmt.methodCall.typeArguments))
    param_indexes = extern_param_indexes[(extern_type, m.member)] if (extern_type, m.member) in extern_param_indexes else []
    types = [m.type.parameters.parameters[par].type for par in param_indexes]

    # the indexes of the parameters which originate from a type parameter
    # TODO generalize and move to hlir16_attrs
    default_extern_opts = (True, [], None, None)
    # TODO add a way to issue compile time/runtime warnings (addWarning), e.g. if there is a buffer overflow

    externs = {
        ('bytes',   'meter',        'execute_meter'): ( True, [],        ["{0}", "{2}", "{3}"],            ["{0}[(uint32_t)({1}) - 1]", "*((uint32_t*)({2}))"]),
        ('packets', 'counter',      'count'):         ( True, [],        ["{0}", "int", "uint32_t"],       ["{0}[(uint32_t)({1}) - 1]", "{1}", "1"]),
        ('bytes',   'counter',      'count'):         ( True, [],        ["{0}", "int", "uint32_t"],       ["REPLACED_BELOW"]),
        (None,      'register',     'read'):          ( True, ["&({})"], ["register_{0}*", "{1}*", "{2}"], None),
        (None,      'register',     'write'):         ( True, ["{}"],    ["register_{0}*", "int", "{2}"],  ["{0}", "(int)({1})", "{2}"]),
        (None,      'Digest',       'pack'):          (False, [],        ["{1}*"],                         None),
    }

    extern_params = (packets_or_bytes, extern_type, m.member)
    type_args_in_fun_name, expr_args, type_par_reformat, arg_reformat = externs[extern_params] if extern_params in externs else default_extern_opts

    if packets_or_bytes == 'bytes':
        varname = generate_var_name("packet_size_bytes");
        #pre[ uint32_t $varname = pd->parsed_length;
        arg_reformat = ["{0}[(uint32_t)({1}) - 1]", "{1}", varname]

    type_params2 = paramtypes + [format_type(resolve_type(par.type, type_params)) for par in parameters]
    if type_par_reformat is not None:
        type_params2 = [fmt.format(*type_params2) for fmt in type_par_reformat]
    if type_params2[2]=="uint16_t" and type_params2[0]=='register_uint32_t*':
        type_params2[0]='register_uint16_t*'
    if type_params2[2]=="uint8_t" and type_params2[0]=='register_uint32_t*':
        type_params2[0] = 'register_uint8_t*'
    type_params_str = ", ".join(type_params2)
    (a, par) = method_args[0]
    if expr_args != []:
        ee = expr.expression
        # TODO if 'meta', use the appropriate field of all_metadatas

        if ee.node_type == "Constant":
            local_name = str(0)
        else:
            c=ee._expr

            try:
                if ee._expr.path.name == 'meta':
                    local_name = mprefix + ee.member
                    if(re.match("isInPIT",ee.member)):
                        if (type_params2[2] == "uint32_t"):
                            #[ uint32_t* tmp${ee.member}= (uint32_t*)malloc(32*sizeof(uint32_t));
                        elif(type_params2[2] == "uint16_t"):
                            #[ uint16_t* tmp${ee.member}= (uint16_t*)malloc(16*sizeof(uint16_t));
                        local_name = "tmp" + ee.member
                        expr_args[0] = "{}"
                    if(re.match("name_hash",ee.member)):
                        if (type_params2[2] == "uint32_t"):
                            #[ uint32_t* tmp${ee.member}= (uint32_t*)malloc(32*sizeof(uint32_t));
                        elif(type_params2[2] == "uint16_t"):
                            #[ uint16_t* tmp${ee.member}= (uint16_t*)malloc(16*sizeof(uint16_t));
                        local_name = "tmp" + ee.member
                        expr_args[0] = "{}"
                    if(re.match("isInCS",ee.member)):
                        if (type_params2[2] == "uint32_t"):
                            #[ uint32_t* tmp${ee.member}= (uint32_t*)malloc(32*sizeof(uint32_t));
                        elif(type_params2[2] == "uint16_t"):
                            #[ uint16_t* tmp${ee.member}= (uint16_t*)malloc(16*sizeof(uint16_t));
                        local_name = "tmp" + ee.member
                        expr_args[0] = "{}"
                        expr_args[0] = "{}"
                    if(re.match("pkg_number",ee.member)):
                        if (type_params2[2] == "uint32_t"):
                            #[ uint32_t* tmp${ee.member}= (uint32_t*)malloc(32*sizeof(uint32_t));
                        elif(type_params2[2] == "uint16_t"):
                            #[ uint16_t* tmp${ee.member}= (uint16_t*)malloc(16*sizeof(uint16_t));
                        local_name = "tmp" + ee.member
                        expr_args[0] = "{}"
                else:
                    local_name = mprefix + ee.expr.path.name
                    if(re.match("standard_metadata",ee.expr.path.name)):
                        if (type_params2[2] == "uint32_t"):
                            #[ uint32_t* tmp${ee.expr.path.name}= (uint32_t*)malloc(32*sizeof(uint32_t));
                        elif(type_params2[2] == "uint16_t"):
                            #[ uint16_t* tmp${ee.expr.path.name}= (uint16_t*)malloc(16*sizeof(uint16_t));
                        local_name = "tmp" + ee.expr.path.name
                        expr_args[0] = "{}"
            except:
                try:
                    if ee._expr.path.name == 'meta':
                        local_name = mprefix + ee.member
                    else:
                        local_name = mprefix + ee.path.name
                except:
                    local_name = gen_extern_format_parameter(c,par)
        # local_name = str(ee.value) if ee.node_type == "Constant" else mprefix + ee.member if ee._expr.path.name == 'meta' else mprefix + ee.path.name
        expr_args = [earg.format(local_name) for earg in expr_args]



    type_args = "".join(["_" + format_type(resolve_type(t, type_params)) for t in types])

    with SugarStyle("inline_comment"):
        param_args = [gen_extern_format_parameter(arg.expression, par) for (arg, par) in method_args]
    all_args = [mparname] + expr_args + param_args
    if arg_reformat is not None:
        all_args = [fmt.format(*all_args) for fmt in arg_reformat]
    for all_arg in all_args: 
        if(re.match("pkg_number",all_arg)):
            all_arg = "*({})".format(all_arg)
        

    all_args = ["({})".format(all_args[0])] + all_args[1:]
    all_args = ", ".join(all_args)
    funname_postfix = type_args if type_args_in_fun_name else ""
    #pre[ extern void extern_${mexpr_type.name}_${m.member}${funname_postfix}(${type_params_str});
    #[ extern_${mexpr_type.name}_${m.member}${funname_postfix}(${all_args});
    if expr_args != []:
        ee = expr.expression
        # TODO if 'meta', use the appropriate field of all_metadatas

        if not ee.node_type == "Constant":
            try:
                if ee._expr.path.name == 'meta':
                    if(re.match("isInPIT",ee.member)):
                        #[ MODIFY_INT32_INT32_AUTO_PACKET(pd, header_instance_meta, field_metadata_${ee.member}, *tmp${ee.member});
                    if(re.match("name_hash",ee.member)):
                        #[ MODIFY_INT32_INT32_AUTO_PACKET(pd, header_instance_meta, field_metadata_${ee.member}, *tmp${ee.member});
                    if(re.match("isInCS",ee.member)):
                        #[ MODIFY_INT32_INT32_AUTO_PACKET(pd, header_instance_meta, field_metadata_${ee.member}, *tmp${ee.member});
                    if(re.match("pkg_number",ee.member)):
                        #[ MODIFY_INT32_INT32_AUTO_PACKET(pd, header_instance_meta, field_metadata_${ee.member}, *tmp${ee.member});
                else:
                    local_name = ee.expr.path.name
                    if(re.match("standard_metadata",ee.expr.path.name)):
                        #[ MODIFY_INT32_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_${ee.expr.path.name}_t_${ee.member}, *tmp${ee.expr.path.name});
            except:
                pass


def gen_methodcall(stmt):
    mcall = format_expr(stmt.methodCall)

    if mcall:
        #[ $mcall;
    else:
        addWarning('generating method call statement', 'Invalid method call {}'.format(stmt.methodCall))
        #[ /* unhandled method call ${stmt.methodCall} */


################################################################################

def resolve_reference(e):
    if hasattr(e, 'field_ref'):
        h = e.expr.header_ref
        f = e.field_ref
        return (h, f)
    else:
        return e

def is_subsequent((h1,f1), (h2, f2)):
    if hasattr(h1, 'type'):
        fs = h1.type.type_ref.fields.vec
    else:
        fs = h1.type_ref.field.vec
    return h1 == h2 and fs.index(f1) + 1 == fs.index(f2)

def groupby(xs, fun):
    """Groups the elements of a list.
    The upcoming element will be grouped if
    fun(last element of the group, upcoming) evaluates to true."""
    if not xs:
        yield []
        return

    elems = []
    for x in xs:
        if elems == []:
            elems = [x]
        elif not fun(elems[-1], x):
            yield elems
            elems = [x]
        else:
            elems.append(x)

    if elems != []:
        yield elems

def group_references(refs):
    for xs in groupby(refs, lambda x1, x2: isinstance(x1, tuple) and isinstance(x2, tuple) and is_subsequent(x1, x2)):
        if xs == [None]:
            # TODO investigate this case further
            continue
        
        yield (xs[0][0], map(lambda (hdr, fld): fld, xs))

def fldid(h, f):
    inst_type_name = 'all_metadatas' if h._type._type_ref.is_metadata else h.ref.name if h.node_type == 'PathExpression' else h.name
    return 'field_instance_{}_{}'.format(inst_type_name, f.name)
def fldid2(h, f): return h.id + ',' +  f.id


# A set of expression IDs that have already been generated.
generated_exprs = set()

def convert_component(component):
    if component.node_type == 'Member':
        hdr      = component.expr
        fld_name = component.member
        fld      = hdr.type.fields.get(fld_name)
        return (component.node_type, hdr, fld)

    if component.node_type == 'Constant':
        return (component.node_type, component.value, "")

    addWarning('generating list expression buffer', 'Skipping not supported list element %s' % component)
    return None

def listexpression_to_buf(expr):
    def width(hdr, fld):
        if fld.is_vw: return 'field_desc(pd, %s).bitwidth'%fldid(hdr, fld)
        return str(fld.size)

    s = ""
    o = '0'
    # TODO add support for component.node_type == 'Constant'
    components = [('tuple', c[0], c[1]) if type(c) == tuple else convert_component(c) for c in map(resolve_reference, expr.components)]
    components = [(c[1], c[2]) for c in components if c is not None if c[0] != 'Constant']
    for h, fs in group_references(components):
        w = '+'.join([width(h, f) for f in fs])
        s += 'memcpy(buffer%s + (%s+7)/8, field_desc(pd, %s).byte_addr, (%s+7)/8);\n' % (expr.id, o, fldid(h, fs[0]), w)
        o += '+'+w
    return 'int buffer{0}_size = ({1}+7)/8;\nuint8_t buffer{0}[buffer{0}_size];\n'.format(expr.id, o) + s

################################################################################

def gen_method_isValid(e):
    if hasattr(e.method.expr, 'header_ref'):
        #[ (pd->headers[${e.method.expr.header_ref.id}].pointer != NULL)
    else:
        #[ (pd->headers[${format_expr(e.method.expr)}].pointer != NULL)

def gen_method_setInvalid(e):
    if hasattr(e.method.expr, 'header_ref'):
        #[ pd->headers[${e.method.expr.header_ref.id}].pointer = NULL
    else:
        #[ pd->headers[${format_expr(e.method.expr)}].pointer = NULL

def gen_method_apply(e):
    #[ ${e.method.expr.path.name}_apply(STDPARAMS_IN)

def gen_method_setValid(e):
    h = e.method.expr.header_ref

    # TODO fix: f must always have an is_vw attribute
    def is_vw(f):
        if f.get_attr('is_vw') is None:
            return False
        return f.is_vw

    # TODO is this the max size?
    length = (sum([f.size if not is_vw(f) else 0 for f in h.type.type_ref.fields])+7)/8

    #[ pd->headers[${h.id}] = (header_descriptor_t) {
    #[     .type = ${h.id},
    #[     .length = $length,
    #[     .pointer = calloc(${h.type.type_ref.byte_width}, sizeof(uint8_t)),
    #[     /*TODO determine and set this field*/
    #[     .var_width_field_bitwidth = 0,
    #[ };

def print_with_base(number, base):
    if base == 16:
        return "0x{0:x}".format(number)
    if base == 2:
        return "0b{0:b}".format(number)

    return "{}".format(number)

def gen_format_expr(e, format_as_value=True, expand_parameters=False):
    simple_binary_ops = {'Div':'/', 'Mod':'%',                                 #Binary arithmetic operators
                         'Grt':'>', 'Geq':'>=', 'Lss':'<', 'Leq':'<=',         #Binary comparison operators
                         'BAnd':'&', 'BOr':'|', 'BXor':'^',                    #Bitwise operators
                         'LAnd':'&&', 'LOr':'||',                              #Boolean operators
                         'Equ':'==', 'Neq':'!='}                               #Equality operators

    # TODO currently, AddSat and SubSat are handled exactly as Add and Sub
    complex_binary_ops = {'AddSat':'+', 'SubSat':'-', 'Add':'+', 'Sub':'-', 'Mul':'*', 'Shl':'<<', 'Shr':'>>'}
    
    if e is None:
        return "FORMAT_EXPR(None)"
    elif e.node_type == 'DefaultExpression':
        return "default"
    elif e.node_type == 'Parameter':
        return format_type(e.type) + " " + e.name
    elif e.node_type == 'Constant':
        if e.type.node_type == 'Type_Bits':
            if e.type.size > 32:
                def split_text(text, n):
                    """Splits the text into chunks that are n characters long."""
                    return [text[i:i+n] for i in range(0, len(text), n)]

                byte_width = (e.type.size+7)/8
                const_str_format = '{:0' + str(2 * byte_width) + 'x}'
                const_str = const_str_format.format(e.value)
                array_const = ", ".join(["0x" + txt for txt in split_text(const_str, 2)])
                var_name = generate_var_name("const", "0x" + const_str)

                #pre[ uint8_t ${var_name}[] = {$array_const};

                return var_name
            else:
                value_hint = "" if e.type.size <= 4 or e.value < 2**(e.type.size-1) else " /* probably -{} */".format(2**e.type.size - e.value)
                # 4294967136 versus (uint32_t)4294967136
                return "({}){}{}".format(format_type(e.type), print_with_base(e.value, e.base), value_hint)
                
        else:
            return str(e.value)
    elif e.node_type == 'BoolLiteral':
        return 'true' if e.value else 'false'
    elif e.node_type == 'StringLiteral':
        return '"' + e.value + '"';
    elif e.node_type == 'TypeNameExpression':
        return format_expr(e.typeName.type_ref);

    elif e.node_type == 'Neg':
        if e.type.node_type == 'Type_Bits' and not e.type.isSigned:
            return '(' + format_type_mask(e.type) + '(' + str(2**e.type.size) + '-' + format_expr(e.expr) + '))'
        else:
            return '(-' + format_expr(e.expr) + ')'
    elif e.node_type == 'Cmpl':
        return '(' + format_type_mask(e.type) + '(~' + format_expr(e.expr) + '))'
    elif e.node_type == 'LNot':
        return '(!' + format_expr(e.expr) + ')'

    elif e.node_type in simple_binary_ops and e.node_type == 'Equ' and e.left.type.size > 32:
        return "0 == memcmp({}, {}, ({} + 7) / 8)".format(format_expr(e.left), format_expr(e.right), e.left.type.size)

    elif e.node_type in simple_binary_ops:
        return '(({}){}({}))'.format(format_expr(e.left), simple_binary_ops[e.node_type], format_expr(e.right))

    #Subtraction on unsigned values is performed by adding the negation of the second operand
    elif e.node_type == 'Sub' and e.type.node_type == 'Type_Bits' and not e.type.isSigned:
        return '(' + format_type_mask(e.type) + '(' + format_expr(e.left) + '+(' + str(2**e.type.size) + '-' + format_expr(e.right) + ')))'
    #Right shift on signed values is performed with a shift width check
    elif e.node_type == 'Shr' and e.type.node_type == 'Type_Bits' and e.type.isSigned:
        return '(({1}>{2}) ? 0 : ({0} >> {1}))'.format(format_expr(e.left), format_expr(e.right), e.type.size)
    #These formatting rules MUST follow the previous special cases
    elif e.node_type in complex_binary_ops:
        temp_expr = '(' + format_expr(e.left,expand_parameters=True) + complex_binary_ops[e.node_type] + format_expr(e.right,expand_parameters=True) + ')'
        if e.type.node_type == 'Type_InfInt':
            return temp_expr
        elif e.type.node_type == 'Type_Bits':
            if not e.type.isSigned:
                return '(' + format_type_mask(e.type) + temp_expr + ')'
            else:
                if e.type.size in {8,16,32}:
                    return '((' + format_type(e.type) + ') ' + temp_expr + ')'
                else:
                    addError('formatting an expression', 'Expression of type %s is not supported on int<%s>. (Only int<8>, int<16> and int<32> are supported.)' % (e.node_type, e.type.size))
                    return ''

    elif e.node_type == 'Mux':
        return '(' + format_expr(e.e0) + '?' + format_expr(e.e1) + ':' + format_expr(e.e2) + ')'

    elif e.node_type == 'Slice':
        return '(' + format_type_mask(e.type) + '(' + format_expr(e.e0) + '>>' + format_expr(e.e2) + '))'

    elif e.node_type == 'Concat':
        return '((' + format_expr(e.left) + '<<' + str(e.right.type.size) + ') | ' + format_expr(e.right) + ')'

    elif e.node_type == 'Cast':
        if e.expr.type.node_type == 'Type_Bits' and not e.expr.type.isSigned and e.expr.type.size == 1 \
                and e.destType.node_type == 'Type_Boolean':        #Cast from bit<1> to bool
            return '(' + format_expr(e.expr) + ')'
        elif e.expr.type.node_type == 'Type_Boolean' and e.destType.node_type == 'Type_Bits' and not e.destType.isSigned \
                and e.destType.size == 1:                          #Cast from bool to bit<1>
            return '(' + format_expr(e.expr) + '? 1 : 0)'
        elif e.expr.type.node_type == 'Type_Bits' and e.destType.node_type == 'Type_Bits':
            if e.expr.type.isSigned == e.destType.isSigned:
                if not e.expr.type.isSigned:                       #Cast from bit<w> to bit<v>
                    if e.expr.type.size > e.destType.size:
                        return '(' + format_type_mask(e.destType) + format_expr(e.expr) + ')'
                    else:
                        if (expand_parameters):
                            return format_expr(e.expr, expand_parameters = True)
                        else:
                            return format_expr(e.expr)
                else:                                              #Cast from int<w> to int<v>
                    return '((' + format_type(e.destType) + ') ' + format_expr(e.expr) + ')'
            elif e.expr.type.isSigned and not e.destType.isSigned: #Cast from int<w> to bit<w>
                return '(' + format_type_mask(e.destType) + format_expr(e.expr) + ')'
            elif not e.expr.type.isSigned and e.destType.isSigned: #Cast from bit<w> to int<w>
                if e.destType.size in {8,16,32}:
                    return '((' + format_type(e.destType) + ')' + format_expr(e.expr) + ')'
                else:
                    addError('formatting an expression', 'Cast from bit<%s> to int<%s> is not supported! (Only int<8>, int<16> and int<32> are supported.)' % e.destType.size)
                    return ''
        #Cast from int to bit<w> and int<w> are performed by P4C
        addError('formatting an expression', 'Cast from %s to %s is not supported!' % (pp_type_16(e.expr.type), pp_type_16(e.destType)))
        return ''

    elif e.node_type == 'ListExpression':
        if e.id not in generated_exprs:
            prepend_statement(listexpression_to_buf(e))
            generated_exprs.add(e.id)
        return '(struct uint8_buffer_s) {{ .buffer =  buffer{}, .buffer_size = buffer{}_size }}'.format(e.id, e.id)
        # return 'buffer{}, buffer{}_size'.format(e.id, e.id)
    elif e.node_type == 'SelectExpression':
        #Generate local variables for select values
        for k in e.select.components:
            varname = gen_var_name(k)
            if k.type.node_type == 'Type_Bits' and k.type.size <= 32:
                #pre[ ${format_type(k.type)} $varname = ${format_expr(k)};
            elif k.type.node_type == 'Type_Bits' and k.type.size % 8 == 0:
                #pre[ uint8_t $varname[${k.type.size/8}];
                #pre[ EXTRACT_BYTEBUF_PACKET(pd, ${format_expr(k, False)}, $varname);'
            else:
                addError('formatting select expression', 'Select on type %s is not supported!' % pp_type_16(k.type))

        cases = []
        for case in e.selectCases:
            cases_tmp = case.keyset.components if case.keyset.node_type == 'ListExpression' else [case.keyset]
            conds = []
            for k, c in zip(e.select.components, cases_tmp):
                select_type = k.type.node_type
                size = k.type.size #if k.type.node_type == 'Type_Bits' else 0
                case_type = c.node_type

                if case_type == 'DefaultExpression':
                    conds.append('true /* default */')
                elif case_type == 'Constant' and select_type == 'Type_Bits' and 32 < size and size % 8 == 0:
                    byte_array = int_to_big_endian_byte_array_with_length(c.value, size/8)
                    #pre[ uint8_t ${gen_var_name(c)}[${size/8}] = ${byte_array};
                    conds.append('memcmp({}, {}, {}) == 0'.format(gen_var_name(k), gen_var_name(c), size/8))
                elif size <= 32:
                    if case_type == 'Range':
                        conds.append('{0} <= {1} && {1} <= {2}'.format(format_expr(c.left), gen_var_name(k), format_expr(c.right)))
                    elif case_type == 'Mask':
                        conds.append('({0} & {1}) == ({2} & {1})'.format(format_expr(c.left), format_expr(c.right), gen_var_name(k)))
                    else:
                        if case_type not in {'Constant'}: #Trusted expressions
                            addWarning('formatting a select case', 'Select statement cases of type %s on %s might not work properly.'
                                       % (case_type, pp_type_16(k.type)))
                        conds.append('{} == {}'.format(gen_var_name(k), format_expr(c)))
                else:
                    addError('formatting a select case', 'Select statement cases of type %s on %s is not supported!'
                             % (case_type, pp_type_16(k.type)))
            cases.append('if({0}){{parser_state_{1}(pd, buf, tables, pstate);}}'.format(' && '.join(conds), format_expr(case.state)))
        return '\nelse\n'.join(cases)

    elif e.node_type == 'PathExpression':
        if e.ref.name == "standard_metadata":
            prepend_statement(pathexpression_to_buf(e))
            return '(struct uint8_buffer_s) {{ .buffer = buffer{}, .buffer_size = buffer{}_size }}'.format(e.id, e.id)
        if e.ref.name == 'session_0':
            return "global_smem." + e.ref.name
        if is_control_local_var(e.ref.name) and expand_parameters == True:
            return "global_smem." + e.ref.name
        if is_control_local_var(e.ref.name):
            return "local_vars->" + e.ref.name
        if expand_parameters and not e.path.absolute:
            return "parameters." + e.ref.name

        return e.ref.name

    elif e.node_type == 'Member':
        if hasattr(e, 'field_ref'):
            if format_as_value == False:
                return fldid(e.expr.header_ref, e.field_ref) # originally it was fldid2

            if e.type.size > 32:
                var_name = generate_var_name("hdr_{}_{}".format(e.expr.header_ref.id, e.field_ref.id))
                byte_size = (e.type.size + 7) / 8

                #pre[ uint8_t* ${var_name}[${byte_size}];
                #pre[ EXTRACT_BYTEBUF_PACKET(pd, ${e.expr.header_ref.id}, ${e.field_ref.id}, ${var_name});

                return var_name
            if e.expr.header_ref._type.type_ref.is_metadata and e.expr.path.name == "meta":
                hdrinst = 'header_instance_meta'
            elif e.expr.header_ref._type.type_ref.is_metadata:
                hdrinst = 'header_instance_all_metadatas'
            else:
                hdrinst = e.expr.header_ref.id
            #hdrinst = 'header_instance_all_metadatas' if e.expr.header_ref._type.type_ref.is_metadata else e.expr.header_ref.id
            return '(GET_INT32_AUTO_PACKET(pd, {}, {}))'.format(hdrinst, e.field_ref.id)
        elif hasattr(e, 'header_ref'):
            # TODO do both individual meta fields and metadata instance fields
            if e.header_ref.name == 'metadata':
                #[ pd->fields.field_instance_${e.expr.member}_${e.member}
            return e.header_ref.id
        elif e.expr.node_type == 'PathExpression':
            var = e.expr.ref.name

            if e.expr.type.node_type == 'Type_Header':
                h = e.expr.type
                return '(GET_INT32_AUTO_PACKET(pd, header_instance_{}, field_{}_{}))'.format(var, h.name, e.member)
            else:
                #[ ${format_expr(e.expr)}.${e.member}
        else:
            if e.type.node_type in {'Type_Enum', 'Type_Error'}:
                #[ ${e.type.members.get(e.member).c_name}
            elif e.expr('expr', lambda e2: e2.type.name == 'parsed_packet'):
                #[ pd->fields.field_instance_${e.expr.member}_${e.member}
            else:
                #[ ${format_expr(e.expr)}.${e.member}
    # TODO some of these are formatted as statements, we shall fix this
    elif e.node_type == 'MethodCallExpression':
        special_methods = {
            ('Member', 'setValid'):     gen_method_setValid,
            ('Member', 'isValid'):      gen_method_isValid,
            ('Member', 'setInvalid'):   gen_method_setInvalid,
            ('Member', 'apply'):        gen_method_apply,
        }

        method = special_methods.get((e.method.node_type, e.method.member)) if e.method.get_attr('member') is not None else None

        if method:
            #[ ${method(e)}
        elif e.arguments.is_vec() and e.arguments.vec != []:
            # TODO is this right? shouldn't e.method always have a .ref?
            if e.method.get_attr('ref') is None:
                mref = e.method.expr.ref
                method_params = mref.type.type_ref.typeParameters
            else:
                mref = e.method.ref
                method_params = mref.type.parameters

            if mref.name == 'digest':
                return gen_format_call_digest(e)
            else:
                return gen_format_call_extern(e, mref, method_params)
        else:
            if e.method('expr').type.node_type == 'Type_Extern':
                if e.method.member in {'advance', 'length'}:
                    raise NotImplementedError('{}.{} is not supported yet!'.format(e.method.expr.type.name, e.method.member))

                funname = "{}_t_{}".format(e.method.expr.type.name, e.method.member)
                if e.method.member in {'lookahead'}:
                    len = e.typeArguments[0].size
                    extern_type = format_type(e.method.expr.type.methods.get(e.method.member, 'Method').type.returnType)
                    prepend_statement("uint8_t lk_ahead_len={};\n".format(len))
                    prepend_statement("{}(pd,lk_ahead_len,buf);\n".format(funname))
                    #[ (LOOKAHEAD(lk_ahead_len,lkahead_data))
                else:
                    extern_inst = format_expr(e.method.expr)
                    extern_type = format_type(e.method.expr.type.methods.get(e.method.member, 'Method').type.returnType)
                    prepend_statement("extern {} {}({}_t);\n".format(extern_type, funname, e.method.expr.type.name))
                    #[ $funname($extern_inst)
            else:
                funname = format_expr(e.method)
                prepend_statement("extern void {}(SHORT_STDPARAMS);\n".format(funname))
                #[ $funname(SHORT_STDPARAMS_IN)
    elif e.node_type == 'Argument':
        return format_expr(e.expression)
    elif e.node_type == 'StructInitializerExpression':
        #{ (${gen_format_type(e.type)}) {
        for component in e.components:
            tref = component.expression.expr("ref.type.type_ref")
            if tref and tref.is_metadata:
                #[ .${component.name} = (GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_${tref.name}_${component.expression.member})),
            else:
                if component.expression.type.size <= 32:
                    #[ .${component.name} = ${gen_format_expr(component.expression)},
                else:
                    #[ /* ${component.name}/${component.expression.type.size}b will be initialised afterwards */
        #} }
    elif e.node_type == 'StructExpression':
        varname = gen_var_name(e)
        #pre[ ${format_type(e.type)} $varname;
        for component in e.components:
            tref = component.expression.expr("ref.type.type_ref")
            if tref and tref.is_metadata:
                #pre[ $varname.${component.name} = (GET_INT32_AUTO_PACKET(pd, header_instance_all_metadatas, field_${tref.name}_${component.expression.member}));
            else:
                if component.expression.type.size <= 32:
                    #pre[ $varname.${component.name} = ${gen_format_expr(component.expression)};
                else:
                    indirection = "&" if is_primitive(component.expression.type) else ""
                    refbase = "local_vars->" if is_control_local_var(component.name) else 'parameters.'
                    bitsize = (component.expression.type.size+7)/8
                    hdrinst = component.expression.expr.header_ref.name
                    fldinst = component.expression.member
                    #pre[ EXTRACT_BYTEBUF_PACKET(pd, header_instance_$hdrinst, field_instance_${hdrinst}_$fldinst, &($varname.${component.name}));
        #[ $varname
    else:
        addError("formatting an expression", "Expression of type %s is not supported yet!" % e.node_type)


# TODO remove duplication (actions, dataplane)
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

def gen_format_call_extern(e, mref, method_params):
    # TODO temporary fix, this will be computed later on
    with types({
        "T": "struct uint8_buffer_s",
        "O": "unsigned",
        "HashAlgorithm": "int",
        "D": "uint16_t",
        "M": "uint32_t",
        "P": "uint32_t*"
    }):
        fmt_params = format_method_parameters(e.arguments, method_params)
        all_params = ", ".join([p for p in [fmt_params, "SHORT_STDPARAMS_IN"] if p != ''])

        return_type = format_type(mref.type.returnType)
        param_types = ", ".join([format_type(tpar) for (par, tpar) in method_parameters_by_type(e.arguments, method_params)] + ["SHORT_STDPARAMS"])
        #pre[ extern ${format_type(e.type)} ${mref.name}(${param_types});
        #[ ${mref.name}($all_params)

def gen_format_call_digest(e):
    #pre[ #ifdef PPK_NO_CONTROL_PLANE
    #pre[ #error "Generating digest when PPK_NO_CONTROL_PLANE is defined"
    #pre[ #endif

    #pre[ debug("    " T4LIT(<,outgoing) " " T4LIT(Sending digest,outgoing) " to port " T4LIT(%d,port) "\n", ${e.arguments[0].expression.value});
    for c in e.arguments[1].expression.components:
        cexpr = c.expression
        hdr = cexpr.expr.path.name if cexpr.expr('header_ref', lambda h: h._type._type_ref.is_metadata) else cexpr.expr.header_ref._type_ref.name
        #pre[ dbg_bytes(field_desc(pd, field_instance_${hdr}_${cexpr.member}).byte_addr, (${cexpr.type.size}+7)/8, "        : "T4LIT(${cexpr.member},field)"/"T4LIT(${cexpr.type.size})" = ");
    #aft[ sleep_millis(300);

    id = e.id
    name = e.typeArguments['Type_Name'][0].path.name
    receiver = e.arguments[0].expression.value
    
    #pre[ ctrl_plane_digest digest$id = create_digest(bg, "$name");
    for fld in e.arguments[1].expression.components:
        bitsize = fld.expression.type.size
        fe = fld.expression
        hdr = fe.expr.path.name if fe.expr('header_ref', lambda h: h._type._type_ref.is_metadata) else fe.expr.header_ref._type_ref.name
        #pre[ add_digest_field(digest$id, field_desc(pd, field_instance_${hdr}_${fe.member}).byte_addr, $bitsize);

    #[ send_digest(bg, digest$id, $receiver)

################################################################################

def format_declaration(d, varname_override = None):
    global file_sugar_style
    with SugarStyle("no_comment"):
        return gen_format_declaration(d, varname_override)

# TODO use the variable_name argument in all cases where a variable declaration is created
def format_type(t, variable_name = None, resolve_names = True, addon = ""):
    global file_sugar_style
    with SugarStyle("inline_comment"):
        
        result = gen_format_type(t, resolve_names, variable_name is not None, addon).strip()

        if variable_name is None:
            return result

        split = result.split(" ")
        essential_portion = 2 if split[0] in ['enum', 'struct'] else 1
        return "{} {}{}".format(" ".join(split[0:essential_portion]), variable_name, " ".join(split[essential_portion:]))

def format_method_parameters(ps, mt):
    global file_sugar_style
    with SugarStyle("inline_comment"):
        return gen_format_method_parameters(ps, mt)

def format_expr(e, format_as_value=True, expand_parameters=False):
    global file_sugar_style
    with SugarStyle("inline_comment"):
        return gen_format_expr(e, format_as_value, expand_parameters)

def format_statement(stmt, ctl=None):
    global enclosing_control
    if ctl is not None:
        enclosing_control = ctl

    global pre_statement_buffer
    global post_statement_buffer
    pre_statement_buffer = ""
    post_statement_buffer = ""

    ret = gen_format_statement(stmt)

    pre_statement_buffer_ret = pre_statement_buffer
    pre_statement_buffer = ""
    post_statement_buffer_ret = post_statement_buffer
    post_statement_buffer = ""
    return pre_statement_buffer_ret + ret + post_statement_buffer_ret


def format_type_mask(t):
    global file_sugar_style
    with SugarStyle("inline_comment"):
        return gen_format_type_mask(t)

def gen_var_name(item, prefix = None):
    if not prefix:
        prefix = "value_" + str(item.node_type)
    #[ ${prefix}_${item.id}

def pathexpression_to_buf(expr):
    s = ""
    o = '0'
    for h in expr.type.fields:
        w = '+'+ str(h.type.size)
        s += 'memcpy(buffer%s + (%s+7)/8, field_desc(pd, field_standard_metadata_t_%s).byte_addr, (%s+7)/8);\n' % (expr.id, o, h.name, w)
        o += w
    return 'int buffer{0}_size = ({1}+7)/8;\nuint8_t buffer{0}[buffer{0}_size];\n'.format(expr.id,  o) +s
