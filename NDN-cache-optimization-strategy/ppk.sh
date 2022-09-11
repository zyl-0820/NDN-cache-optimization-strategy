#!/bin/bash
pkill -f "controller"
mkdir -p pcap

KNI_STORAGE="0"
exit_program() {
    echo -e "$nn"
    [ "${OPTS[ctr]}" != "" ] && verbosemsg "(Terminating controller $(cc 0)dpdk_${OPTS[ctr]}_controller$nn)" && sudo killall -q "dpdk_${OPTS[ctr]}_controller"
    [ "$1" != "" ] && errmsg "$(cc 3)Error$nn: $*"
    exit $ERROR_CODE
}

optvalue() {
#	echo "optvalue function"
    [ "${IGNORE_OPTS["$1"]}" != "" ] && echo "off" && return
    [ "${OPTS[$1]}" == "" ] && echo "off" && return
    echo "${OPTS[$1]}"
}

get_current_envs() {
    ( set -o posix ; set ) | tr '\n' '\r' | sed "s/\r[^=]*='[^']*\r[^\r]*'\r/\r/g" | tr '\r' '\n'
}

errmsg() {
    for msgvar in "$@"; do
        (>&2 echo -e "$msgvar")
    done
}

array_contains() {
    local value=$1
    shift

    for ((i=1;i <= $#;i++)) {
        [ "${!i}" == "${value}" ] && echo "y" && return
    }
    echo "n"
}

cc() {
    [ "$(array_contains "${OPTS[bw]}" "on" "terminal")" == y ] && echo "$nn" && return

    while [ $# -gt 0 ]; do
        [ "${colours[$1]}" != "" ] && echo "${colours[$1]}" && return
        shift
    done
    echo "$nn"
}

verbosemsg() {
    [ "$(optvalue verbose)" != off ] && msg "$@"
    return 0
}

setopt() {
    [ "${OPTS["$1"]}" == "off" ] && echo -e "Option ${OPTS["$1"]} is set to be ignored" && return
    OPTS[$1]="$2"
}


set_term_light() {
    OPTS[light]=$1
    colours=()

    [ "$1" == "0" ] && nn="" && return

    IFS=',' read -r -a optparts <<< "$1"
    for i in "${!optparts[@]}"; do 
        COLOUR=${optparts[$i]}
        COLOUR=${KNOWN_COLOURS[$COLOUR]-$COLOUR}

        colours[$i]="\033[${COLOUR}m"
    done
    nn="\033[0m"
}

overwrite_on_difference() {
    cmp -s "/tmp/$1.tmp" "$2/$1"
    [ "$?" -ne 0 ] && mv "/tmp/$1.tmp" "$2/$1"
    rm -f "/tmp/$1.tmp"
}

addopt() {
    OPTS[$1]="${OPTS[$1]:+${OPTS[$1]}$3}${2}"
}

msg() {
    [ "$(optvalue silent)" != off ] && return

    for msgvar in "$@"; do
        echo -e "$msgvar"
    done
}

exit_on_error() {
    ERROR_CODE=$?
    [ "$ERROR_CODE" -eq 0 ] && return

    exit_program "$1 (error code: $(cc 3)$ERROR_CODE$nn)"
}

print_cmd_opts() {
    IFS=' ' read -r -a cflags <<< "$1"

    NEXT_IS_OPT=0    
    for cflag in ${cflags[@]}; do
        [ $NEXT_IS_OPT -eq 1 ] && NEXT_IS_OPT=0 && echo "$(cc 1)${cflag}$nn" && continue

        IFS='=' read -r -a parts <<< "$cflag"

        KNOWN_OPT_FLAGS=(-g --p4v -U --log-level -c -n --config -p)

        [ "$(array_contains "${parts[0]}" "${KNOWN_OPT_FLAGS[@]}")" == y ] && NEXT_IS_OPT=1

        OPTTXT1=${parts[0]}
        OPTTXT2=""
        OPTTXT3=""
        OPTTXT4=""

        [[ "${parts[0]}" == -*  ]]   && OPTTXT1="-"  && OPTTXT3=${parts[0]##-}
        [[ "${parts[0]}" == -D* ]]   && OPTTXT1="-D" && OPTTXT3=${parts[0]##-D}
        [[ "${parts[0]}" == --* ]]   && OPTTXT1="--" && OPTTXT3=${parts[0]##--}
        [[ "${parts[0]}" == *.p4* ]] && OPTTXT1="${parts[0]%/*}/" && OPTTXT2="${parts[0]##*/}" && OPTTXT2="${OPTTXT2%%.p4*}" && OPTTXT4=".${parts[0]##*.}"

        echo "$(cc 0)$OPTTXT1$(cc 1)$OPTTXT2$nn$(cc 2)$OPTTXT3$nn${parts[1]+=$(cc 1)${parts[1]}}$(cc 2 0)$OPTTXT4$nn$nn"
    done | tr '\n' ' '
}


ORIG_ENVS=`get_current_envs | cut -f 1 -d"=" | paste -sd "|" -`

echo $#
echo $1

ERROR_CODE=1

COLOURS_CONFIG_FILE=${COLOURS_CONFIG_FILE-./cfg/colours.cfg}
LIGHTS_CONFIG_FILE=${LIGHTS_CONFIG_FILE-./cfg/lights.cfg}
EXAMPLES_CONFIG_FILE=${EXAMPLES_CONFIG_FILE-./cfg/examples.cfg}

P4_SRC_DIR=${P4_SRC_DIR-"./examples/"}
CTRL_PLANE_DIR=${CTRL_PLANE_DIR-./ppk/shared/ctrl_plane}

ARCH=${ARCH-dpdk}
ARCH_OPTS_FILE=${ARCH_OPTS_FILE-./cfg/opts_${ARCH}.cfg}

PYTHON=${PYTHON-python}
DEBUGGER=${DEBUGGER-gdb}
declare -A EXT_TO_VSN=(["p4"]=16 ["p4_14"]=14)
echo $EXT_TO_VSN
ALL_COLOUR_NAMES=(action bytes control core default error expected extern field header headertype incoming off outgoing packet parserstate port smem socket status success table testcase warning)
declare -A KNOWN_COLOURS
declare -A OPTS
declare -A IGNORE_OPTS
colours=()
nn="\033[0m"
echo ${P4C}
[ "${P4C}" == "" ] && exit_program "\$P4C not defined"
[ "$ARCH" == "dpdk" ] && [ "${RTE_SDK}" == "" ] && exit_program "\$RTE_SDK not defined"



    PYTHON_PARSE_OPT=$(cat <<END
import re
import sys

# To facilitate understanding, almost all named patterns of the regex are separated
patterns = (
    ("cond",      '!condvar(=!condval)?!condsep'),
    ("prefix",    '(\^|:|::|%|%%|@)'),
    ("condvar",   '[a-zA-Z0-9_\-.]+'),
    ("condval",   '[^\s].*'),
    ("condsep",   '(\s*->\s*)'),
    ("letop",     '\+{0,2}='),
    ("letval",    '[^\s].*'),
    ("var",       '[a-zA-Z0-9_\-.]+'),
    ("comment",   '\s*(;.*)?'),
    )

rexp = '^(!prefix|!cond?)?!var(?P<let>\s*!letop?\s*!letval)?!comment$'

# Assemble the full regex
for pattern, replacement in patterns:
    rexp = rexp.replace("!" + pattern, "(?P<{}>{})".format(pattern, replacement))

rexp = re.compile(rexp)

m = re.match(rexp, sys.argv[1])

print 'ok', ('y' if m is not None else 'n')
for gname in (p[0] for p in patterns):
    print gname, '' if m is None else m.group(gname) or ''
END
    )


candidate_count() {
    simple_count=$(find "$P4_SRC_DIR" -type f -name "$1.p4*" | wc -l)
    if [ $simple_count -eq 1 ]; then
        echo 1
    else
        echo $(find "$P4_SRC_DIR" -type f -name "*$1*.p4*" | wc -l)
    fi
}

candidates() {
    if [ $(candidate_count $1) -gt 0 ]; then
        echo
        find "$P4_SRC_DIR" -type f -name "*$1*.p4*" | sed 's#^.*/\([^\.]*\).*$#    \1#g'
    else
        echo "(no candidates found)"
    fi
}

reserve_hugepages2() {
    HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`
    OLD_HUGEPAGES=`cat /sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages`
    if [ $OLD_HUGEPAGES -lt ${OPTS[hugepages]} ]; then
        verbosemsg "Reserving $(cc 0)${OPTS[hugepages]} hugepages$nn (previous size: $(cc 0)$OLD_HUGEPAGES$nn)"

        echo "echo ${OPTS[hugepages]} > /sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" > .echo_tmp
        sudo sh .echo_tmp
        rm -f .echo_tmp
    else
        verbosemsg "Using $(cc 0)$OLD_HUGEPAGES hugepages$nn (sufficient, as $(cc 0)${OPTS[hugepages]}$nn are needed)"
    fi
}



OPT_NOPRINTS=("OPT_NOPRINTS" "cfgfiles")
CFGFILES=${CFGFILES-${COLOURS_CONFIG_FILE},${LIGHTS_CONFIG_FILE},!cmdline!,!varcfg!${EXAMPLES_CONFIG_FILE},${ARCH_OPTS_FILE}}
declare -A OPTS=([cfgfiles]="$CFGFILES")

echo "cfgfile: $CFGFILES"

while [ "${OPTS[cfgfiles]}" != "" ]; do
    IFS=',' read -r -a cfgfiles <<< "${OPTS[cfgfiles]}"
    OPTS[cfgfiles]=""

    echo "cfgfiles: ${cfgfiles[@]}"
    echo "OPTS[cfgfiles]: ${OPTS[cfgfiles]}"
    for cfgfile in ${cfgfiles[@]}; do
        declare -a NEWOPTS=()

        # Collect option descriptions either from the command line or a file
        if [ "$cfgfile" == "!cmdline!" ]; then
        	echo "cmdline1"
            OPT_ORIGIN="$(cc 0)command line$nn"
            for opt; do
            	echo "opt： $opt"
                NEWOPTS+=("$opt")
            done
        elif [[ $cfgfile =~ !varcfg!* ]]; then
        	echo "varcfg1";
            OPT_ORIGIN="$(cc 0)variant config file$nn $(cc 1)${cfgfile#!varcfg!}$nn"
            examplename="${OPTS[example]}@${OPTS[variant]}"
            [ "${OPTS[variant]}" == "std" ] && examplename="${OPTS[example]}\(@std\)\?"
            IFS=$'\n'
            while read -r opts; do
                IFS=' ' read -r -a optparts <<< "$opts"
                for opt in ${optparts[@]}; do
                    if [[ $opt == @* ]]; then
                        collected_opts=""
                        # option can refers to another option in the same file
                        while read -r opts2; do
                            IFS=' ' read -r -a optparts2 <<< `echo $opts2 | sed -e "s/^$opt//g"`

                            # skip the first element, which is textually the same as $opt
                            for opt2 in ${optparts2[@]}; do
                                NEWOPTS+=("$opt2")
                            done
                        done < <(cat "${cfgfile#!varcfg!}" | grep -e "^$opt\s" | sed -e "s/^[^ \t]+[ \t]*//g")
                    else
                        NEWOPTS+=("$opt")
                    fi
                done
            done < <(cat "${cfgfile#!varcfg!}" | grep -e "^$examplename\s" | sed -e "s/^[^ \t]+[ \t]*//g")
        else
        	echo "else1 start;"
            OPT_ORIGIN="$(cc 0)file$nn $(cc 1)${cfgfile}$nn"
            echo "OPT_ORIGIN : ${OPT_ORIGIN}"
            IFS=$'\n'
            while read -r opt; do
                NEWOPTS+=("$opt")
            done < <(cat "${cfgfile}")
#            echo "NEWOPTS: ${NEWOPTS[@]}"
            echo "else1 end;"
        fi

        # printf 'IIIIIIIIIIIII %s\n' "${NEWOPTS[@]}"
        verbosemsg "Parsing $OPT_ORIGIN"

        # Process the options
        for opt in ${NEWOPTS[@]}; do
            if [[ $opt == *.p4* ]] && [ -f "$opt" ]; then
                setopt example "$(basename ${opt%.*})"
                setopt source "$opt"
                continue
            fi
            # Split the option into its components along the above regex
            IFS=' '
            declare -A groups=() && while read -r grpid grptxt; do groups["$grpid"]="$grptxt"; done < <(python -c "$PYTHON_PARSE_OPT" "$opt")
            [ "${groups[ok]}" == n ] && [[ $opt = *\;* ]] && continue
            [ "${groups[ok]}" == n ] && echo -e "Cannot parse option $(cc 0)$opt$nn (origin: $OPT_ORIGIN)" && continue
            var="${groups[var]}"
            value="${groups[letval]:-on}"
            [ "${groups[neg]}" != "" ] && OPTS[$var]=off && continue

            if [ "${groups[cond]}" != "" ]; then
                expected_value="${groups[condval]}"
                [ "$(optvalue "${groups[condvar]}")" == off ] && continue
                [ "$expected_value" != "" -a "${OPTS[${groups[condvar]}]}" != "$expected_value" ] && continue
            fi

            [[ $var == COLOUR_* ]] && KNOWN_COLOURS[${var#COLOUR_}]="$value"
            [ "$var" == "light" ] && set_term_light "$value" && continue

            [ "$var" == cfgfiles -a ! -f "$value" ] && echo -e "Config file $(cc 0)$value$nn cannot be found" && continue

            if [ "$(array_contains "${groups[prefix]}" ":" "::" "%" "%%")" == y ]; then
            	echo "the value of var is ${var}"
                FIND_COUNT=$(candidate_count "${var}")
                [ $FIND_COUNT -gt 1 ] && exit_program "Name is not unique: found $(cc 1)$FIND_COUNT$nn P4 files for $(cc 0)${var}$nn, candidates: $(cc 1)$(candidates ${var})$nn"
                [ $FIND_COUNT -eq 0 ] && exit_program "Could not find P4 file for $(cc 0)${var}$nn, candidates: $(cc 1)$(candidates ${var})$nn"

                setopt example "$var"
                setopt source "`find "$P4_SRC_DIR" -type f -name "${var}.p4*"`"
            fi

            [ "${groups[prefix]}" == ":"  ] && setopt example "$var" && continue
            [ "${groups[prefix]}" == "::" ] && setopt example "$var" && setopt dbg on && continue
            [ "${groups[prefix]}" == "%"  ] && [ "$value" == "on" ]  && verbosemsg "Test case not specified for example $(cc 0)$var$nn, using $(cc 1)test$nn as default" && value="test"
            [ "${groups[prefix]}" == "%"  ] && setopt example "$var" && setopt testcase "$value" && setopt variant test && continue
            [ "${groups[prefix]}" == "%%" ] && [ "$value" == "on" ] && setopt example "$var" && setopt suite on && setopt dbg on && setopt variant test && continue
            [ "${groups[prefix]}" == "%%" ] && setopt example "$var" && setopt testcase "$value" && setopt dbg on && setopt variant test && continue
            [ "${groups[prefix]}" == "@"  ] && setopt variant "$var" && continue
            [ "${groups[prefix]}" == "^"  ] && IGNORE_OPTS["$var"]=on && continue
            [ "${groups[letop]}" == "+="  ] && addopt "$var" "$value" " " && echo "ldhtest  $var   $value" && continue
            [ "${groups[letop]}" == "++=" ] && addopt "$var" "$value" "\n" && continue

            setopt "$var" "$value"
        done

        # Steps after processing the command line
        if [ "$cfgfile" == "!cmdline!" ]; then
            # The command line must specify an example to run
            echo " optvalue: ${IGNORE_OPTS["$1"]}"
            [ "$(optvalue example)" == off ] && exit_program "No example to run"
            # The variant has to be determined before processing the config files.
            [ "$(optvalue variant)" == off ] && setopt variant std
        fi
    done
done

[ "$(optvalue verbose)" == on ] && IGNORE_OPTS[silent]=on
[ "$(optvalue silent)" == on  ] && IGNORE_OPTS[verbose]=on

[ "$(optvalue variant)" == off ] && [ "$(optvalue testcase)" != off -o "$(optvalue suite)" != off ] && OPTS[variant]=test && verbosemsg "Variant $(cc 1)@test$nn is chosen because testing is requested"
[ "${OPTS[variant]}" == "" -o "${OPTS[variant]}" == "-" ] && OPTS[variant]=std && verbosemsg "Variant $(cc 1)@std$nn is automatically chosen"


# Determine version by extension if possible
if [ "${OPTS[vsn]}" == "" ]; then
    P4_EXT="$(basename "${OPTS[source]}")"
    P4_EXT=${P4_EXT##*.}
    if [ "$(array_contains "${P4_EXT##*.}" ${!EXT_TO_VSN[@]})" == n ]; then
        exit_program "Cannot determine P4 version for the extension $(cc 0)${P4_EXT}$nn of $(cc 0)$(print_cmd_opts "${OPTS[source]}")$nn"
    fi
    OPTS[vsn]="${EXT_TO_VSN["${P4_EXT##*.}"]}"
    [ "${OPTS[vsn]}" == "" ] && exit_program "Cannot determine P4 version for $(cc 0)${OPTS[example]}$nn"
    verbosemsg "Determined P4 version to be $(cc 0)${OPTS[vsn]}$nn by the extension of $(cc 0)$(print_cmd_opts "${OPTS[source]}")$nn"
fi


PPK_TARGET_DIR=${PPK_TARGET_DIR-"./build/${OPTS[choice]}"}
OPTS[executable]="$PPK_TARGET_DIR/build/${OPTS[example]}"
PPK_SRCGEN_DIR=${PPK_SRCGEN_DIR-"$PPK_TARGET_DIR/srcgen"}
PPK_GEN_INCLUDE_DIR="${PPK_SRCGEN_DIR}"
PPK_GEN_INCLUDE="gen_include.h"
GEN_MAKEFILE_DIR="${PPK_TARGET_DIR}"
GEN_MAKEFILE="Makefile"

PPK_LOG_DIR=${PPK_LOG_DIR-$(dirname $(dirname ${OPTS[executable]}))/log}

if [ "${OPTS[p4]}" != on ] && [ "${OPTS[c]}" != on ] && [ "${OPTS[run]}" != on ]; then
    OPTS[p4]=on
    OPTS[c]=on
    OPTS[run]=on
fi

if [ "${OPTS[kni]}" == on ] ; then
    KNI_STORAGE="1"
    echo "123456" |sudo -S insmod ${RTE_SDK}/x86_64-native-linuxapp-gcc/kmod/rte_kni.ko carrier=on
    sed -i 's/\#define KNI_STORAGE.*/\#define KNI_STORAGE 1/g' ppk/dpdk/includes/dpdk_nicon.h
else
    KNI_STORAGE="0"
    sed -i 's/\#define KNI_STORAGE.*/\#define KNI_STORAGE 0/g' ppk/dpdk/includes/dpdk_nicon.h
fi
if [ "${OPTS[vlan]}" == on ] ; then
    sed -i 's/\#define PPK_VLAN.*/\#define PPK_VLAN 1/g' ppk/dpdk/includes/dpdk_nicon.h
else
    sed -i 's/\#define PPK_VLAN.*/\#define PPK_VLAN 0/g' ppk/dpdk/includes/dpdk_nicon.h
fi

mkdir -p $PPK_TARGET_DIR
mkdir -p $PPK_SRCGEN_DIR

[ "$(optvalue silent)" != off ] && addopt makeopts ">/dev/null" " "

# Phase 0a: Check for required programs
if [ "$(optvalue c)" != off -a ! -f "$P4C/build/p4test" ]; then
    exit_program "cannot find P4C compiler at $(cc 1)\$P4C/build/p4test$nn"
fi

if [ "$(optvalue run)" != off ]; then
    verbosemsg "Requesting root access..."
    echo "123456" | sudo -S echo -n ""
    verbosemsg "Root access granted, starting..."
fi

start_time1=`date "+%Y-%m-%d %H:%M:%S"`     #获取当前时间，例：2015-03-11 12:33:41       
starttimeStamp1=`date -d "$start_time1" +%s`      #将start_time转换为时间戳，精确到秒
startStamp1=$((starttimeStamp1*1000+`date "+%N"`/1000000)) #将current转换为时间戳，精确到毫秒
# Phase 1: P4 to C compilation
if [ "$(optvalue p4)" != off ]; then
    msg "[$(cc 0)COMPILE  P4-${OPTS[vsn]}$nn] $(cc 0)$(print_cmd_opts ${OPTS[source]})$nn@$(cc 1)${OPTS[variant]}$nn${OPTS[testcase]+, test case $(cc 1)${OPTS[testcase]-(none)}$nn}${OPTS[dbg]+, $(cc 0)debug$nn mode}"

    addopt p4opts "${OPTS[source]}" " "
    addopt p4opts "--p4v ${OPTS[vsn]}" " "
    addopt p4opts "-g ${PPK_SRCGEN_DIR}" " "
    # addopt p4opts "-desugar_info none" " "
    [ "$(optvalue verbose)" != off ] && addopt p4opts "-verbose" " "

    verbosemsg "P4 compiler options: $(print_cmd_opts "${OPTS[p4opts]}")"

    IFS=" "
    echo ${OPTS[p4opts]}
    $PYTHON -B compiler/compiler.py ${OPTS[p4opts]}
    exit_on_error "P4 to C compilation failed"
fi

end_time1=`date "+%Y-%m-%d %H:%M:%S"`     #获取当前时间，例：2015-03-11 12:33:41       
endtimeStamp1=`date -d "$end_time1" +%s`      #将start_time转换为时间戳，精确到秒
endStamp1=$((endtimeStamp1*1000+`date "+%N"`/1000000)) #将current转换为时间戳，精确到毫秒

compileTime1=$[endStamp1-startStamp1]
msg "[p4 to C cost  $compileTime1 milliseconds]"
# Phase 2: C compilation
start_time=`date "+%Y-%m-%d %H:%M:%S"`     #获取当前时间，例：2015-03-11 12:33:41       
starttimeStamp=`date -d "$start_time" +%s`      #将start_time转换为时间戳，精确到秒
startStamp=$((starttimeStamp*1000+`date "+%N"`/1000000)) #将current转换为时间戳，精确到毫秒

echo "ppk_gen_include is ${PPK_GEN_INCLUDE}"
if [ "$(optvalue c)" != off ]; then
    cat <<EOT > "/tmp/${PPK_GEN_INCLUDE}.tmp"
#ifndef __GEN_INCLUDE_H_
#define __GEN_INCLUDE_H_
EOT

    for colour in ${ALL_COLOUR_NAMES[@]}; do
        COLOUR_MACRO=""
        [ "$(array_contains "${OPTS[bw]}" "on" "switch")" == n ] && COLOUR_MACRO="\"${OPTS[${OPTS[T4LIGHT_$colour]}]-${OPTS[T4LIGHT_$colour]}}\"  // ${OPTS[T4LIGHT_$colour]}"
        [ "$(array_contains "${OPTS[bw]}" "on" "switch")" == n ] && [ "$COLOUR_MACRO" == "\"\"" ] && [ "$colour" != "default" ] && COLOUR_MACRO="T4LIGHT_default"
        echo "#define T4LIGHT_${colour} $COLOUR_MACRO" >> "/tmp/${PPK_GEN_INCLUDE}.tmp"
    done

    IFS=" "
    for hdr in ${OPTS[include-hdrs]}; do
        echo "#include \"$hdr\"" >> "/tmp/${PPK_GEN_INCLUDE}.tmp"
    done

    echo "#endif" >> "/tmp/${PPK_GEN_INCLUDE}.tmp"
    overwrite_on_difference "${PPK_GEN_INCLUDE}" "${PPK_GEN_INCLUDE_DIR}"

    cat <<EOT >"/tmp/${GEN_MAKEFILE}.tmp"
CDIR := \$(dir \$(lastword \$(MAKEFILE_LIST)))
APP = ${OPTS[example]}
include \$(CDIR)/../makefiles/${ARCH}_backend_pre.mk
include \$(CDIR)/../makefiles/common.mk
include \$(CDIR)/../makefiles/hw_independent.mk
VPATH += $(dirname ${OPTS[source]})
EXTRA_CFLAGS += ${OPTS[extra-cflags]}
LDFLAGS += ${OPTS[ldflags]}
EOT


    IFS=" "
    for src in ${OPTS[include-srcs]}; do
        echo "SRCS-y += $src" >> "/tmp/${GEN_MAKEFILE}.tmp"
    done

    echo "CFLAGS += ${OPTS[cflags]}" >> "/tmp/${GEN_MAKEFILE}.tmp"
    echo "include \$(CDIR)/../makefiles/${ARCH}_backend_post.mk" >> "/tmp/${GEN_MAKEFILE}.tmp"

    overwrite_on_difference "${GEN_MAKEFILE}" "${GEN_MAKEFILE_DIR}"


    msg "[$(cc 0)COMPILE SWITCH$nn]"
    verbosemsg "C compiler options: $(cc 0)$(print_cmd_opts "${OPTS[cflags]}")${nn}"
    echo "${PPK_TARGET_DIR}"
    cd ${PPK_TARGET_DIR}
    if [ "$(optvalue silent)" != off ]; then
        make -j >/dev/null
    else
        make -j
    fi
    exit_on_error "C compilation failed"

    cd - >/dev/null
fi
end_time=`date "+%Y-%m-%d %H:%M:%S"`     #获取当前时间，例：2015-03-11 12:33:41       
endtimeStamp=`date -d "$end_time" +%s`      #将start_time转换为时间戳，精确到秒
endStamp=$((endtimeStamp*1000+`date "+%N"`/1000000)) #将current转换为时间戳，精确到毫秒

compileTime=$[endStamp-startStamp]
msg "[C to Bin cost  $compileTime milliseconds]"
# Phase 3B: Execution (controller)
if [ "$(optvalue run)" != off ]; then
    if [ "$(optvalue ctr)" == off ]; then
        msg "[$(cc 0)NO  CONTROLLER$nn]"
    else
        mkdir -p ${PPK_LOG_DIR}

        CONTROLLER="dpdk_${OPTS[ctr]}_controller"
        CONTROLLER_LOG=${PPK_LOG_DIR}/controller.log

        sudo killall -q "$CONTROLLER"

        msg "[$(cc 0)RUN CONTROLLER$nn] $(cc 1)${CONTROLLER}$nn (default for $(cc 0)${OPTS[example]}$nn@$(cc 1)${OPTS[variant]}$nn)"

        verbosemsg "Controller log : $(cc 0)${CONTROLLER_LOG}$nn"
        verbosemsg "Controller opts: $(print_cmd_opts ${OPTS[ctrcfg]})"

        # Step 3A-1: Compile the controller
        cd $CTRL_PLANE_DIR
        if [ "$(optvalue silent)" != off ]; then
            make -s -j $CONTROLLER >/dev/null
        else
            make -s -j $CONTROLLER
        fi
        exit_on_error "Controller compilation failed"
        cd - >/dev/null

        # Step 3A-3: Run controller
        if [ $(optvalue showctl optv) == y ]; then
            stdbuf -o 0 $CTRL_PLANE_DIR/$CONTROLLER ${OPTS[ctrcfg]} &
        else
            (stdbuf -o 0 $CTRL_PLANE_DIR/$CONTROLLER ${OPTS[ctrcfg]} >&2> "${CONTROLLER_LOG}" &)
        fi
        sleep 0.05
    fi
fi





# Phase 3B: Execution (switch)
if [ "$(optvalue run)" != off ]; then
    msg "[$(cc 0)RUN SWITCH$nn] $(cc 1)${OPTS[executable]}$nn"

    sudo mkdir -p /mnt/huge

    grep -s '/mnt/huge' /proc/mounts > /dev/null
    if [ $? -ne 0 ] ; then
        sudo mount -t hugetlbfs nodev /mnt/huge
    fi

    [ "$(optvalue hugepages)" != off ] && reserve_hugepages2 "${OPTS[hugepages]}"
    if [ "$KNI_STORAGE" == "1" ]; then
        [ "$ARCH" == "dpdk" ] && EXEC_OPTS="${OPTS[ealopts-ppk-kni]} -- ${OPTS[cmdopts-ppk-kni]}"
    else
        [ "$ARCH" == "dpdk" ] && EXEC_OPTS="${OPTS[ealopts]} -- ${OPTS[cmdopts]}"
    fi
    verbosemsg "Options    : $(print_cmd_opts "${EXEC_OPTS}")"

    echo "arch :  $ARCH"
    if [ "$KNI_STORAGE" == "1" ]; then
        echo "ealopts: ${OPTS[ealopts-ppk-kni]}"
        echo "cmdopts: ${OPTS[cmdopts-ppk-kni]}"
    else
        echo "ealopts: ${OPTS[ealopts]}"
        echo "cmdopts: ${OPTS[cmdopts]}"
    fi
   
    echo "hugepages: ${OPTS[hugepages]}"
    echo "exec_opts: ${EXEC_OPTS}"


    mkdir -p ${PPK_LOG_DIR}
    echo "Executed at $(date +"%Y%m%d %H:%M:%S")" >${PPK_LOG_DIR}/last.txt
    echo >>${PPK_LOG_DIR}/last.txt
    if [ "${OPTS[eal]}" == "off" ]; then
        sudo -E "${OPTS[executable]}" ${EXEC_OPTS} 2>&1 | egrep -v "^EAL: " \
            |& tee >( tee -a ${PPK_LOG_DIR}/last.lit.txt | sed 's/\x1B\[[0-9;]*[JKmsu]//g' >> ${PPK_LOG_DIR}/last.txt ) \
            |& tee >( tee ${PPK_LOG_DIR}/$(date +"%Y%m%d_%H%M%S")_${OPTS[choice]}.lit.txt | sed 's/\x1B\[[0-9;]*[JKmsu]//g' > ${PPK_LOG_DIR}/$(date +"%Y%m%d_%H%M%S")_${OPTS[choice]}.txt )
        # note: PIPESTATUS is bash specific
        ERROR_CODE=${PIPESTATUS[0]}
    else
        sudo -E "${OPTS[executable]}" ${EXEC_OPTS} \
            |& tee >( tee -a ${PPK_LOG_DIR}/last.lit.txt | sed 's/\x1B\[[0-9;]*[JKmsu]//g' >> ${PPK_LOG_DIR}/last.txt ) \
            |& tee >( tee ${PPK_LOG_DIR}/$(date +"%Y%m%d_%H%M%S")_${OPTS[choice]}.lit.txt | sed 's/\x1B\[[0-9;]*[JKmsu]//g' > ${PPK_LOG_DIR}/$(date +"%Y%m%d_%H%M%S")_${OPTS[choice]}.txt )
        ERROR_CODE=${PIPESTATUS[0]}
    fi

    command -v errno >&2>/dev/null
    ERRNO_EXISTS=$?
    [ $ERRNO_EXISTS -eq 0 ] && [ $ERROR_CODE -eq 0 ] && ERR_CODE_MSG="($(cc 0)`errno $ERROR_CODE`$nn)"
    [ $ERRNO_EXISTS -eq 0 ] && [ $ERROR_CODE -ne 0 ] && ERR_CODE_MSG="($(cc 3 2 1)`errno $ERROR_CODE`$nn)"

    [ $ERROR_CODE -eq 139 ] && ERR_CODE_MSG="($(cc 3 2 1)Segmentation fault$nn)"
    [ $ERROR_CODE -eq 255 ] && ERR_CODE_MSG="($(cc 2 1)Switch execution error$nn)"

    [ $ERROR_CODE -eq 0 ] && msg "${nn}PPK switch exited $(cc 0)normally$nn"
    [ $ERROR_CODE -ne 0 ] && msg "\n${nn}PPK switch running $(cc 0)$(print_cmd_opts "${OPTS[source]}")$nn exited with error code $(cc 3 2 1)$ERROR_CODE$nn $ERR_CODE_MSG"
    [ $ERROR_CODE -ne 0 ] && msg " - Runtime options were: $(print_cmd_opts "${EXEC_OPTS}")"

    DBGWAIT=1
    if [ $ERROR_CODE -ne 0 ] && [ "$(optvalue autodbg)" != off ]; then
        [ "${OPTS[ctr]}" != "" ] && verbosemsg "Restarting controller $(cc 0)dpdk_${OPTS[ctr]}_controller$nn" && sudo killall -q "dpdk_${OPTS[ctr]}_controller"
        (stdbuf -o 0 $CTRL_PLANE_DIR/$CONTROLLER ${OPTS[ctrcfg]} &)

        msg "Running $(cc 1)debugger $DEBUGGER$nn in $(cc 0)$DBGWAIT$nn seconds"
        sleep $DBGWAIT
        print "${OPTS[executable]}"
        sudo -E ${DEBUGGER} -q -ex run --args "${OPTS[executable]}" ${EXEC_OPTS}
    fi
fi

exit_program
