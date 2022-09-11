# 存放代码
### PPK是一个可编程自定义的软件交换机
- cfg存放配置文件
- compiler存放后端编译器文件
- examples存放p4源码写的一些例子及流表
- makefiles存放mk文件
- ppk存放项目源代码
- build生成p4编译器编译后的c源代码

### 项目环境
- DPDK19.11
- P4C
- gRPC
- protobuf 3.0
- PI
- python3
- GCC/Clang
- LLD/gold/bfd

### 程序安装
安装本项目，可执行脚本bootstrap.sh，脚本自动安装相关的环境（DPDK, P4C, P4Runtime等）以及下载项目本身源码，并配置环境变量
bootstrap.cfg配置相关环境的版本信息
安装完成后，相关的环境变量保存在ppk_en.sh中

### 程序运行
1. ```shell```. ./ppk_en.sh
2. ```shell```./ppk.sh :example
3. dbg模式 ```shell``` ./ppk.sh ::example 或者./ppk.sh :example dbg
4. 分步模式
    - ```shell```./ppk.sh :example p4
    - ```shell```./ppk.sh :example c
    - ```shell```./ppk.sh :example run