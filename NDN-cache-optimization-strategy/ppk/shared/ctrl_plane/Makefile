CC=gcc
CFLAGS=-Wall -pthread -std=c99
LIB=

ifneq ($(P4_GCC_OPTS),)
CFLAGS += $(P4_GCC_OPTS)
endif


all: dpdk_dummy_controller dpdk_portfwd_controller dpdk_l2fwd_controller dpdk_psa_l2fwd_controller dpdk_l3fwd_controller dpdk_smgw_controller dpdk_l2_dst_controller dpdk_l2_src_controller dpdk_l3-ipv4_controller dpdk_l2l3_dst_controller dpdk_l4l3_dst_controller dpdk_geo_dst_controller dpdk_ipv4_dst_controller dpdk_register_controller dpdk_mffwd_controller dpdk_ethernetPowerllink_controller dpdk_fenpian_controller dpdk_encrycard_controller dpdk_decrypt_controller

controllers_common: handlers.c controller.c messages.c sock_helpers.c threadpool.c fifo.c
	$(CC) $(CFLAGS) $(LIB) handlers.c controller.c messages.c sock_helpers.c threadpool.c fifo.c dpdk_ctrl_common.c -c
	ld -r handlers.o controller.o messages.o sock_helpers.o threadpool.o fifo.o dpdk_ctrl_common.o -o dpdk_ctrl.o

dpdk_dummy_controller: controllers_common dpdk_dummy_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_dummy_controller.c -o dpdk_dummy_controller

dpdk_portfwd_controller: controllers_common dpdk_portfwd_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_portfwd_controller.c -o dpdk_portfwd_controller

dpdk_l2fwd_controller: controllers_common dpdk_l2fwd_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l2fwd_controller.c -o dpdk_l2fwd_controller

dpdk_psa_l2fwd_controller: controllers_common dpdk_psa_l2fwd_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_psa_l2fwd_controller.c -o dpdk_psa_l2fwd_controller

dpdk_test-digest_controller: controllers_common dpdk_test-digest_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_test-digest_controller.c -o dpdk_test-digest_controller

dpdk_l3fwd_controller: controllers_common dpdk_l3fwd_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l3fwd_controller.c -o dpdk_l3fwd_controller

dpdk_multimodal_routing_controller: controllers_common dpdk_multimodal_routing_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_multimodal_routing_controller.c -o dpdk_multimodal_routing_controller

dpdk_geo_dst_controller: controllers_common dpdk_geo_dst_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_geo_dst_controller.c -o dpdk_geo_dst_controller

dpdk_ipv6_dst_controller: controllers_common dpdk_ipv6_dst_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_ipv6_dst_controller.c -o dpdk_ipv6_dst_controller

dpdk_l2_dst_controller: controllers_common dpdk_l2_dst_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l2_dst_controller.c -o dpdk_l2_dst_controller

dpdk_l2_src_controller: controllers_common dpdk_l2_src_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l2_src_controller.c -o dpdk_l2_src_controller

dpdk_l3-ipv4_controller: controllers_common dpdk_l3-ipv4_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l3-ipv4_controller.c -o dpdk_l3-ipv4_controller


dpdk_l2l3_dst_controller: controllers_common dpdk_l2l3_dst_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l2l3_dst_controller.c -o dpdk_l2l3_dst_controller

dpdk_l4l3_dst_controller: controllers_common dpdk_l4l3_dst_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l4l3_dst_controller.c -o dpdk_l4l3_dst_controller

dpdk_pinet-ipv4-port_controller: controllers_common dpdk_pinet-ipv4-port_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_pinet-ipv4-port_controller.c -o dpdk_pinet-ipv4-port_controller

dpdk_l3-routing-full_controller: controllers_common dpdk_l3-routing-full_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_l3-routing-full_controller.c -o dpdk_l3-routing-full_controller

dpdk_smgw_controller: controllers_common dpdk_smgw_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_smgw_controller.c -o dpdk_smgw_controller

dpdk_register_controller: controllers_common dpdk_register_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_register_controller.c -o dpdk_register_controller

dpdk_mffwd_controller: controllers_common dpdk_mffwd_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_mffwd_controller.c -o dpdk_mffwd_controller

dpdk_fenpian_controller: controllers_common dpdk_fenpian_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_fenpian_controller.c -o dpdk_fenpian_controller

dpdk_encrycard_controller: controllers_common dpdk_encrycard_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_encrycard_controller.c -o dpdk_encrycard_controller

dpdk_decrypt_controller: controllers_common dpdk_decrypt_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_decrypt_controller.c -o dpdk_decrypt_controller

dpdk_ethernetPowerllink_controller: controllers_common dpdk_ethernetPowerllink_controller.c
	$(CC) $(CFLAGS) $(LIB) dpdk_ctrl.o dpdk_ethernetPowerllink_controller.c -o dpdk_ethernetPowerllink_controller
clean:
	rm -f handlers.o controller.o messages.o sock_helpers.o threadpool.o fifo.o dpdk_ctrl_common.o dpdk_ctrl_common.o dpdk_ctrl.o dpdk_portfwd_controller dpdk_l2fwd_controller dpdk_psa_l2fwd_controller dpdk_l3fwd_controller dpdk_smgw_controller dpdk_dummy_controller dpdk_l2_dst_controller dpdk_l2_src_controller dpdk_l3-ipv4_controller dpdk_l2l3_dst_controller dpdk_l4l3_dst_controller dpdk_pinet-ipv4-port_controller dpdk_geo_dst_controller dpdk_ipv6_dst_controller dpdk_register_controller dpdk_mffwd_controller dpdk_ethernetPowerllink_controller dpdk_fenpian_controller dpdk_encrycard_controller dpdk_decrypt_controller

