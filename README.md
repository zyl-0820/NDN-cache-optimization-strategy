# NDN-cache-optimization-strategy
This repository is an experimental environment for the paper entitled "An NDN cache optimization strategy based on dynamic popularity and replacement value" and is available to the reader to re-implement the caching strategy mentioned in this article. Please get in touch if you have any questions.

### PPK is a programmable custom software switch
- cfg holds the configuration file
- compiler holds the back-end compiler files
- examples holds some examples and flow tables written in p4 source code
- makefiles holds the mk files
- ppk holds the project source code
- build generates the c source code compiled by the p4 compiler

### Project environment
- DPDK19.11
- P4C
- gRPC
- protobuf 3.0
- PI
- python3
- GCC/Clang
- LLD/gold/bfd

### Program installation
To install the project, execute the bootstrap.sh script, which automatically installs the relevant environments (DPDK, P4C, P4Runtime, etc.) as well as downloading the project source code itself and configuring the environment variables
bootstrap.cfg configures the version information of the relevant environment
After installation, the relevant environment variables are stored in ppk_en.sh

### Program running
1. ```shell```. ./ppk_en.sh
2. ```shell```./ppk.sh :example
3. dbg mode ```shell``` ./ppk.sh ::example 或者./ppk.sh :example dbg
4. Step-by-step mode 
    - ```shell```./ppk.sh :example p4
    - ```shell```./ppk.sh :example c
    - ```shell```./ppk.sh :example run
