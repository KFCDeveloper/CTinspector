#ifndef _EBPF_VM_TRANSPORT_RDMA_RC_H_
#define _EBPF_VM_TRANSPORT_RDMA_RC_H_

#include "ebpf_vm_transport.h"

#define EXCH_MSG_PATTERN "0000:000000:000000:0000000000000000:00000000:00000000000000000000000000000000"
#define GID_STR_SIZE 33
// #define UD_GRH_SIZE 40

enum {
	PKT_VM_RDMA_RECV_WRID = 1,
	PKT_VM_RDMA_SEND_WRID = 2
};

struct rdma_addr_message {
	int lid;
	int qpn;
	int psn;
	union ibv_gid gid;
	uint64_t mr_addr;
	uint32_t remote_key;
};

struct rdma_addr_info {
	struct ub_list node;
	struct node_url key;
	struct rdma_addr_message info;
	struct ibv_ah *ah;
};

struct pkt_vm_rdma_state {
	uint32_t pending:1;
	uint32_t should_stop:1;
	uint32_t unused:30;
};

// 执行write的peer: 每个远端内存对应一个起始位置，以及一个当前写的总量
struct start_t_entry {	// mr at remote 
	uint32_t rkey;
	uint64_t r_mr_start;
	uint64_t r_mr_curr_total;	// 已经写的总量
};

// been writen table entry/ 被远端write的peer：这里会记录每块内存上一次被写入的总内存
struct writen_t_entry {
	uint32_t rkey;
	uint64_t r_mr_pre_total;	// 上一次的写入总量
};

struct pkt_vm_rdma_context {
	struct rdma_transport_config cfg;
	struct ibv_context *context;
	struct ibv_comp_channel *channel;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	char *buf;
	int buf_size;
	char *send_buf;
	int send_offset;
	int send_flags;
	int rx_depth;
	pthread_t server_thread;
	struct pkt_vm_rdma_state state;
	struct ibv_port_attr portinfo;
	struct rdma_addr_message local_addr;
	struct ub_list dst_addr_list;
	struct start_t_entry start_table[10];	// 假设注册的内存不会超过10块
	struct writen_t_entry writen_table[10];	// 上一次从远端写入的写入总量，int32是因为立即数只能int32
};

#endif