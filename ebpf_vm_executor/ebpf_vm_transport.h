#ifndef _EBPF_VM_TRANSPORT_H_
#define _EBPF_VM_TRANSPORT_H_

#include <infiniband/verbs.h>

enum {
	PKT_VM_TRANSPORT_TYPE_UDP,
	PKT_VM_TRANSPORT_TYPE_RDMA,
	PKT_VM_TRANSPORT_TYPE_MAX
};

struct node_url {
	uint32_t ip;
	uint16_t port;
	uint16_t reserved;
};

struct rdma_transport_config {
	struct node_url self_url;
	char *ib_devname;
	int ib_port;
	unsigned int max_msg_size;
	unsigned int rx_depth;
	int use_event;
	int gid_index;
	int is_server; // 1: server, 0: client
};

struct udp_transport_config {
	struct node_url self_url;
};

struct transport_config {
	uint32_t transport_type;
	union {
		struct rdma_transport_config rdma_cfg;
		struct udp_transport_config udp_cfg;
	};
};

struct transport_message {
	void *buf;
	int buf_size;
};

struct transport_ops {
	int type;
	void *(*init)(struct transport_config *cfg);
	void (*exit)(void *ctx);
	int (*send)(void *ctx, struct node_url *dst, struct transport_message *msg);
	int (*recv)(void *ctx, struct transport_message *msg);
	void (*return_buf)(void *ctx, struct transport_message *msg);
};

int register_transport(struct transport_ops *ops);

// 用来配合rdma write的自定义协议 地址表
struct rc_write_table{
	uint64_t write_start_addr;	// 从什么内存的什么位置开始写的
	uint32_t current_bl_index;	// 当前正在写的block的index
	uint16_t offset;	// 当前block数据的offset
};

#endif