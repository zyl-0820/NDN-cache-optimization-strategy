#!/bin/bash
#get archtecture of the CPU 
os_bit=$(uname -m | awk '{print " | "$0}')
if [[ $os_bit =~ "x86_64" ]];then
   export DPDK_VSN=19.11
   export RTE_SDK=/home/zhaoxin/PPK/ppk/dpdk-stable-19.11/
   export RTE_TARGET=x86_64-native-linuxapp-gcc
   export P4C=/home/zhaoxin/PPK/ppk/p4c	
   export PPK=ppk
elif [[ $os_bit =~ "aarch64" ]];then
   export DPDK_VSN=Marvell-v8
   export RTE_SDK=/opt/Workspace/P4/ppk/dpdk-Marvell-v8
   export RTE_TARGET=arm64-octeontx2-linuxapp-gcc
   export P4C=/opt/Workspace/P4/ppk/p4c
   export PPK=ppk_arm64
else
   echo "unknown archtecture"
fi
