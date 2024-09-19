#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <infiniband/verbs.h>
#include <errno.h>

#include "ub_list.h"
#include "ebpf_vm_transport_rdma_rc.h"

// static var in rc_pingpong.c 
static int use_dm; // `use_dm` 通常是指是否使用了设备内存（Device Memory）


// var in rc_pingpong.c main func
unsigned int size = 4096;

// whether receive socket msg;
static int if_receive = 0;

// 遍历数组，寻找匹配的 rkey
struct start_t_entry *find_entry(struct start_t_entry start_table[], int size, uint32_t remote_key) {
    for (int i = 0; i < size; i++) {
        if (start_table[i].rkey == remote_key) {
            // 如果找到匹配的 rkey，返回指向该条目的指针
            return &start_table[i];
        }
    }
    // 如果没有找到，返回 NULL
    return NULL;
}

void wire_gid_to_gid(const uint8_t *wgid, union ibv_gid *gid)
{
	uint8_t tmp[9];
	__be32 v32;
	int i;
	uint32_t tmp_gid[4];
	
	for (tmp[8] = 0, i = 0; i < 4; i++) {
		memcpy(tmp, wgid + i * 8, 8);
		sscanf(tmp, "%x", &v32);
		tmp_gid[i] = be32toh(v32);
	}
	memcpy(gid, tmp_gid, sizeof(*gid));
}

void gid_to_wire_gid(const union ibv_gid *gid, uint8_t wgid[])
{
	uint32_t tmp_gid[4];
	int i;
	
	memcpy(tmp_gid, gid, sizeof(tmp_gid));
	for (i = 0; i < 4; ++i) {
		sprintf(&wgid[i * 8], "%08x", htobe32(tmp_gid[i]));
	}
}

static void printf_rdma_addr_message(struct rdma_addr_message *msg)
{
	char gid[33];
	
	inet_ntop(AF_INET6, &msg->gid, gid, sizeof(gid));
	printf("address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x: GID %s\n",
			msg->lid, msg->qpn, msg->psn, gid);
}

static struct rdma_addr_info *pkt_vm_rdma_find_dest(struct pkt_vm_rdma_context *ctx, struct node_url *n)
{
	struct rdma_addr_info *e;
	
	UB_LIST_FOR_EACH(e, node, &ctx->dst_addr_list) {
		if (memcmp(&e->key, n, sizeof(struct node_url)) == 0) {
			return e;
		}
	}
	
	return NULL;
}

static struct rdma_addr_info *pkt_vm_rdma_add_dest(struct pkt_vm_rdma_context *ctx, struct node_url *n, uint8_t *msg, int role)
{
	struct rdma_addr_info *dst;
	uint8_t gid_str[GID_STR_SIZE];
	struct ibv_ah_attr ah_attr = {0};
	
	dst = malloc(sizeof(*dst));
	if (dst == NULL) {
		perror("Failed to allocate memory");
		return NULL;
	}
	
	dst->key.ip = n->ip;
	dst->key.port = n->port;
	dst->key.reserved = 0;
	
	struct rdma_addr_message rdma_addr_info_instance = role? dst->send_info : dst->recv_info;
	
	// sscanf(msg, "%x:%x:%x:%s", &dst->info.lid, &dst->info.qpn, &dst->info.psn, gid_str);
	sscanf(msg, "%04x:%06x:%06x:%016lx:%08x:%s", &rdma_addr_info_instance.lid, &rdma_addr_info_instance.qpn, &rdma_addr_info_instance.psn, &rdma_addr_info_instance.mr_addr, &rdma_addr_info_instance.remote_key, gid_str);
	wire_gid_to_gid(gid_str, &rdma_addr_info_instance.gid);
	// 如果一个rkey从未出现过，则创建一个 start_t_entry
	// struct start_t_entry *result = find_entry(ctx->start_table, 10, dst->info.remote_key);
	// if (result != NULL) {
	// printf("Found entry: rkey = %u, r_mr_start = %lu, r_mr_curr_total = %lu\n",
	// 		result->rkey, result->r_mr_start, result->r_mr_curr_total);
	// } else {
	// 	printf("No matching entry found. Create an entry\n");
	// 	for (int i = 0; i < size; i++) {
	// 		if (ctx->start_table[i].rkey == 0) {  // 发现未使用的条目
	// 			ctx->start_table[i].rkey = dst->info.remote_key;
	// 			ctx->start_table[i].r_mr_start = dst->info.mr_addr;
	// 			ctx->start_table[i].r_mr_curr_total = 0;
	// 			break;
	// 		}else{
	// 			if (i == size - 1){
	// 				fprintf(stderr, "No space in start_table\n");
	// 			}
	// 			continue;
	// 		}
	// 	}
	// }
	
	if (rdma_addr_info_instance.gid.global.interface_id) {
		ah_attr.is_global = 1;
		ah_attr.grh.hop_limit = 1;
		ah_attr.grh.dgid = rdma_addr_info_instance.gid;
		ah_attr.grh.sgid_index = ctx->cfg.gid_index;
	}
	
	ah_attr.dlid = rdma_addr_info_instance.lid;
	ah_attr.port_num = ctx->cfg.ib_port;
	dst->ah = ibv_create_ah(ctx->pd, &ah_attr);
	if (!dst->ah) {
		perror("Failed to create AH");
		return NULL;
	}
	
	ub_list_push_back(&ctx->dst_addr_list, &dst->node);
	printf_rdma_addr_message(&rdma_addr_info_instance);
	return dst;
}

static int pkt_vm_rdma_enable_qp_rc(struct pkt_vm_rdma_context *ctx,struct rdma_addr_message *des)
{
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= IBV_MTU_4096,
		.dest_qp_num	= des->qpn,
		.rq_psn			= des->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= des->lid,
			.sl		= 0,
			.src_path_bits	= 0,
			.port_num	= ctx->cfg.ib_port
		}
	};

	if (des->lid== 0) {
		printf("using gid\n");
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = des->gid;
		attr.ah_attr.grh.sgid_index = ctx->cfg.gid_index;
	}

	if (ibv_modify_qp(ctx->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_AV                 |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER)) {
			fprintf(stderr, "Failed to modify QP to RTR RC\n");
			return 1;
	}
	printf("success to modify QP RTR\n");
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout	    = 14;
	attr.retry_cnt	    = 7;
	attr.rnr_retry	    = 7;
	//attr.sq_psn	    = my_psn;
	attr.max_rd_atomic  = 1;
	attr.sq_psn = ctx->local_addr.psn;
	
	// if (ibv_modify_qp(ctx->qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN)) {
	// 		fprintf(stderr, "Failed to modify QP to RTS RC\n");
	// 		return 1;
	// }
	if (ibv_modify_qp(ctx->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_TIMEOUT            |
			  IBV_QP_RETRY_CNT          |
			  IBV_QP_RNR_RETRY          |
			  IBV_QP_SQ_PSN             |
			  IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "Failed to modify QP to RTS\n");
		return 1;
	}
	printf("success to modify QP RTS\n");
	return 0;
}


static int pkt_vm_rdma_enable_qp_rc_role(struct pkt_vm_rdma_context *ctx,struct rdma_addr_message *des, struct rdma_addr_info *dst, int role)
{
	struct ibv_qp *qp_to_modify = role? dst->send_qp:dst->recv_qp;
	pkt_vm_rdma_get_qp_msg(ctx, dst, role); // 给local qp 赋值，但现在不需要了
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= IBV_MTU_4096,
		.dest_qp_num	= des->qpn,
		.rq_psn			= des->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= des->lid,
			.sl		= 0,
			.src_path_bits	= 0,
			.port_num	= ctx->cfg.ib_port
		}
	};

	if (des->lid== 0) {
		printf("using gid\n");
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = des->gid;
		attr.ah_attr.grh.sgid_index = ctx->cfg.gid_index;
	}

	if (ibv_modify_qp(qp_to_modify, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_AV                 |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER)) {
			fprintf(stderr, "Failed to modify QP to RTR RC\n");
			return 1;
	}
	printf("success to modify QP RTR\n");
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout	    = 14;
	attr.retry_cnt	    = 7;
	attr.rnr_retry	    = 7;
	//attr.sq_psn	    = my_psn;
	attr.max_rd_atomic  = 1;
	attr.sq_psn = ctx->local_addr.psn;
	
	// if (ibv_modify_qp(ctx->qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN)) {
	// 		fprintf(stderr, "Failed to modify QP to RTS RC\n");
	// 		return 1;
	// }
	if (ibv_modify_qp(qp_to_modify, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_TIMEOUT            |
			  IBV_QP_RETRY_CNT          |
			  IBV_QP_RNR_RETRY          |
			  IBV_QP_SQ_PSN             |
			  IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "Failed to modify QP to RTS\n");
		return 1;
	}
	printf("success to modify QP RTS\n");
	return 0;
}


static struct rdma_addr_info *pkt_vm_rdma_get_node_info(struct pkt_vm_rdma_context *ctx, struct node_url *server_url)
{
	uint8_t msg[sizeof(EXCH_MSG_PATTERN)];
	struct sockaddr_in name = {0};
	int sockfd, n;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Failed to create socket");
		return NULL;
	}
	
	name.sin_family = AF_INET;
	name.sin_port = server_url->port;
	name.sin_addr.s_addr = server_url->ip;
	
	if (connect(sockfd, (struct sockaddr *)&name, sizeof(name)) < 0) {
		char svr[32];
		inet_ntop(AF_INET, &name.sin_addr.s_addr, svr, sizeof(svr));
		printf("server = %s, port = %d\n", svr, ntohs(name.sin_port));
		
		perror("Failed to connect to server");
		close(sockfd);
		return NULL;
	}
	
	n = sprintf(msg, "%04x:%06x:%06x:", ctx->local_addr.lid,
				ctx->local_addr.qpn, ctx->local_addr.psn);
	gid_to_wire_gid(&ctx->local_addr.gid, (msg + n));
	
	if (write(sockfd, msg, sizeof(msg)) != sizeof(msg)) {
		perror("Couldn't send local address");
		close(sockfd);
		return NULL;
	}
	
	// 上面先write了自己msg，然后这里先read到对端msg，然后再发送一个done到对端 对端会结束socket
	if (read(sockfd, msg, sizeof(msg)) != sizeof(msg) ||
		write(sockfd, "done", sizeof("done")) != sizeof("done")) {
		perror("Couldn't rea/write remote address");
		close(sockfd);
		return NULL;
	}
	
	close(sockfd);
	return pkt_vm_rdma_add_dest(ctx, server_url, msg, 1);
}

static struct rdma_addr_info *pkt_vm_rdma_write_get_node_info(struct pkt_vm_rdma_context *ctx, struct node_url *server_url, struct rdma_addr_info *dst)
{
	uint8_t msg[sizeof(EXCH_MSG_PATTERN)];
	struct sockaddr_in name = {0};
	int sockfd, n;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Failed to create socket");
		return NULL;
	}
	
	name.sin_family = AF_INET;
	name.sin_port = server_url->port;
	name.sin_addr.s_addr = server_url->ip;
	
	if (connect(sockfd, (struct sockaddr *)&name, sizeof(name)) < 0) {
		char svr[32];
		inet_ntop(AF_INET, &name.sin_addr.s_addr, svr, sizeof(svr));
		printf("server = %s, port = %d\n", svr, ntohs(name.sin_port));
		
		perror("Failed to connect to server");
		close(sockfd);
		return NULL;
	}
	
	// n = sprintf(msg, "%04x:%06x:%06x:", ctx->local_addr.lid,
	// 			ctx->local_addr.qpn, ctx->local_addr.psn, (uint64_t)ctx->mr->addr, ctx->mr->rkey);
	// 作为sender的时候，不需要把自己的 mr 和 rkey 发送过去
	n = sprintf(msg, "%04x:%06x:%06x:%016lx:%08x:", ctx->local_addr.lid,
            	ctx->local_addr.qpn, ctx->local_addr.psn, (uint64_t)0, 0);	// (uint64_t)dst->send_mr->addr, dst->send_mr->rkey
	gid_to_wire_gid(&ctx->local_addr.gid, (msg + n));
	
	if (write(sockfd, msg, sizeof(msg)) != sizeof(msg)) {
		perror("Couldn't send local address");
		close(sockfd);
		return NULL;
	}
	
	// 上面先write了自己msg，然后这里先read到对端msg，然后再发送一个done到对端 对端会结束socket
	if (read(sockfd, msg, sizeof(msg)) != sizeof(msg) ||
		write(sockfd, "done", sizeof("done")) != sizeof("done")) {
		perror("Couldn't rea/write remote address");
		close(sockfd);
		return NULL;
	}
	
	close(sockfd);
	// todo: 实际上是重新创建了一个instance，这样不好
	dst = pkt_vm_rdma_add_dest(ctx, server_url, msg, 1);	// as a sender
}

/**
 * 发送端 需要一个发送qp；接收端需要一个接收qp；想要进行一个单向的rdma write，就会建立两个qp，一个方向会有一对qp；
 * 连接一次socket，就需要创建一个mr和qp
 * 运行该方法的机子此时的角色  role: server: 0, client: 1
 */
static void* pkt_vm_init_after_socket(struct pkt_vm_rdma_context *ctx, struct rdma_addr_message *dst_info, struct rdma_addr_info *dst, int role){
	
	if (role) { // client:1
		dst->send_buf = ctx->buf + ctx->cfg.rx_depth * ctx->cfg.max_msg_size;
		dst->send_offset = 0;
	}
	struct ibv_mr * mr_to_reg = role? dst->send_mr:dst->recv_mr;
	// reg mr
	mr_to_reg = ibv_reg_mr(ctx->pd, ctx->buf, ctx->buf_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
	if (!ctx->mr) {
		fprintf(stderr, "Couldn't register MR\n");
		goto clean_pd;
	}
	
	// create qp
	struct ibv_qp *qp_to_create = role? dst->send_qp:dst->recv_qp;
	{
		struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init_attr = {
			.send_cq = ctx->cq,
			.recv_cq = ctx->cq,
			.cap = {
				.max_send_wr = 1,
				.max_recv_wr = ctx->cfg.rx_depth,
				.max_send_sge = 1,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_RC,
		};
		qp_to_create = ibv_create_qp(ctx->pd, &init_attr);
		if (!qp_to_create) {
			fprintf(stderr, "Couldn't create QP\n");
			goto clean_cq;
		}
		
		ibv_query_qp(qp_to_create, &attr, IBV_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= ctx->cfg.max_msg_size) {
			ctx->send_flags |= IBV_SEND_INLINE;
		}
	}
	// qp init
	{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = ctx->cfg.ib_port,
			.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE
		};

		if (ibv_modify_qp(qp_to_create, &attr,
				IBV_QP_STATE              |
				IBV_QP_PKEY_INDEX         |
				IBV_QP_PORT               |
				IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			goto clean_qp;
		}
	}
	
	pkt_vm_rdma_enable_qp_rc_role(ctx, dst_info, dst, role); // 传入修改qp需要的信息，来自于msg
	
	if (!role) { // server: 0
		// post recv; write_with_imm 需要消耗一个空的 wqe
		int idx;
		for (idx = 0; idx < ctx->cfg.rx_depth; idx++) {
			// ret = pkt_vm_rdma_post_recv(ctx, (ctx->buf + (idx * ctx->cfg.max_msg_size)));
			// simple post recv // todo: 得检查一下这里会不会出问题
			struct ibv_sge list = {
			.addr =  0,
			.length = 0, // todo: 为什么ud的pingpong会+40呢，这里我需要-40吗
			.lkey = 0
			};
			struct ibv_recv_wr wr = {
				.wr_id = 0,
				.sg_list = &list,
				.num_sge = 1,
			};
			struct ibv_recv_wr *bad_wr;
			if (ibv_post_recv(qp_to_create, &wr, &bad_wr) != 0) {
				perror("Failed to post recv buffer");
				goto clean_qp;
			}
		}
	}
	
	return NULL;

	clean_qp:
	ibv_destroy_qp(qp_to_create);

	clean_cq:
		ibv_destroy_cq(ctx->cq);

	clean_mr:
		ibv_dereg_mr(mr_to_reg);

	clean_pd:
		ibv_dealloc_pd(ctx->pd);

	clean_comp_channel:
		if (ctx->channel)
			ibv_destroy_comp_channel(ctx->channel);

	clean_device:
		ibv_close_device(ctx->context);

	clean_buffer:
		free(ctx->buf);

	clean_ctx:
		free(ctx);

	return NULL;
}

static void *pkt_vm_rdma_server_main(void *arg)
{
	struct pkt_vm_rdma_context *ctx = arg;
	struct sockaddr_in name, client_addr;	// client_addr用来保存对端的信息
	socklen_t client_addr_len = sizeof(client_addr);
	int sockfd, reuse_addr;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Failed to create socket");
		return NULL;
	}
	
	reuse_addr = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

	name.sin_family = AF_INET;
	name.sin_port = ctx->cfg.self_url.port;
	name.sin_addr.s_addr = ctx->cfg.self_url.ip;
	
	printf("server listen on port: %d\n", ntohs(name.sin_port));
	
	if (bind(sockfd, (struct sockaddr *)&name, sizeof(name)) < 0) {
		perror("Failed to bind socket");
		close(sockfd);
		return NULL;
	}
	
	if (listen(sockfd, 10) < 0) {
		perror("Failed to listen on socket");
		close(sockfd);
		return NULL;
	}
	
	while (ctx->state.should_stop == 0) {
		uint8_t msg[sizeof(EXCH_MSG_PATTERN)];
		int connfd, n;
		
		connfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
		if (connfd < 0) {
			perror("Failed to accept new connection");
			continue;
		}
		
		n = read(connfd, msg, sizeof(msg));
		if (n != sizeof(msg)) {
			perror("Couldn't read remote address");
			close(connfd);
			continue;
		}
		
		// msg to rdma_addr_message
		uint8_t gid_str[GID_STR_SIZE];
		struct rdma_addr_message * dst_msg;
		dst_msg = (struct rdma_addr_message *)malloc(sizeof(struct rdma_addr_message));
		sscanf(msg, "%04x:%06x:%06x:%016lx:%08x:%s", &dst_msg->lid, &dst_msg->qpn, &dst_msg->psn, &dst_msg->mr_addr, &dst_msg->remote_key, gid_str);
		wire_gid_to_gid(gid_str, &dst_msg->gid);
		
		// add to des linklist
		struct node_url * client_url = (struct node_url *)malloc(sizeof(struct node_url));
		client_url->ip = client_addr.sin_addr.s_addr;
		client_url->port = ntohs(client_addr.sin_port);
		client_url->reserved = 0;
		struct rdma_addr_info *dst  = pkt_vm_rdma_add_dest(ctx, client_url, msg, 0);	// as a server
		dst->send_info = *dst_msg;
		printf("run pkt_vm_rdma_enable_qp in pkt_vm_rdma_server_main!\n");
		
		if (dst->if_recv_init == 0) {
			pkt_vm_init_after_socket(ctx, dst_msg, dst, 0); // role: server
			// pkt_vm_rdma_enable_qp_rc(ctx, dst_msg);  
			dst->if_recv_init = 1;
		}
		// 如果一个rkey从未出现过，则创建一个 start_t_entry
    	// struct start_t_entry *result = find_entry(ctx->start_table, 10, dst_msg->remote_key);
		// if (result != NULL) {
		// printf("Found entry: rkey = %u, r_mr_start = %lu, r_mr_curr_total = %lu\n",
		// 		result->rkey, result->r_mr_start, result->r_mr_curr_total);
		// } else {
		// 	printf("No matching entry found. Create an entry\n");
		// 	for (int i = 0; i < size; i++) {
		// 		if (ctx->start_table[i].rkey == 0) {  // 发现未使用的条目
		// 			ctx->start_table[i].rkey = dst_msg->remote_key;
		// 			ctx->start_table[i].r_mr_start = dst_msg->mr_addr;
		// 			ctx->start_table[i].r_mr_curr_total = 0;
		// 			break;
		// 		}else{
		// 			if (i == size - 1){
		// 				fprintf(stderr, "No space in start_table\n");
		// 			}
		// 			continue;
		// 		}
		// 	}
		// }

		// n = sprintf(msg, "%04x:%06x:%06x:", ctx->local_addr.lid,
					// ctx->local_addr.qpn, ctx->local_addr.psn);
		n = sprintf(msg, "%04x:%06x:%06x:%016lx:%08x:", dst->local_recv_info.lid,
			dst->local_recv_info.qpn, dst->local_recv_info.psn, (uint64_t)dst->recv_mr->addr, dst->recv_mr->rkey);
		gid_to_wire_gid(&dst->local_recv_info.gid, (msg + n));
		
		// 这里是先write，再read；防止read的msg覆盖了write的msg
		if (write(connfd, msg, sizeof(msg)) != sizeof(msg) ||
			read(connfd, msg, sizeof(msg)) != sizeof("done")) {
			perror("Couldn't rea/write remote address");
		}
		close(connfd);
	}
	close(sockfd);
}

static int pkt_vm_rdma_post_recv(struct pkt_vm_rdma_context *ctx, uint8_t *buf)
{
	struct ibv_sge list = {
		.addr =  use_dm ? 0 : (uintptr_t)buf,
		.length = ctx->cfg.max_msg_size, // todo: 为什么ud的pingpong会+40呢，这里我需要-40吗
		.lkey = ctx->mr->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id = (uint64_t)buf,
		.sg_list = &list,
		.num_sge = 1,
	};
	struct ibv_recv_wr *bad_wr;
	
	return ibv_post_recv(ctx->qp, &wr, &bad_wr);
}





static struct pkt_vm_rdma_context *pkt_vm_rdma_init_ctx(struct rdma_transport_config *cfg)
{
	struct ibv_device **dev_list;
	struct ibv_device *ib_dev = NULL;
	struct pkt_vm_rdma_context *ctx;
	int idx;
	
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		perror("Failed to get IB device list");
		return NULL;
	}
	
	for (idx = 0; dev_list[idx]; idx++) {
		if (!strcmp(ibv_get_device_name(dev_list[idx]), cfg->ib_devname)) {
			ib_dev = dev_list[idx];
			break;
		}
	}
	
	if (!ib_dev) {
		fprintf(stderr, "IB device %s not found.\n", cfg->ib_devname);
		return NULL;
	}
	
	ctx = calloc(1, sizeof(*ctx));
	memset(ctx->start_table, 0, sizeof(ctx->start_table));
	memset(ctx->writen_table, 0, sizeof(ctx->writen_table));
	if (!ctx) {
		return NULL;
	}
	
	memcpy(&ctx->cfg, cfg, sizeof(ctx->cfg));
	ctx->send_flags = IBV_SEND_SIGNALED;
	ctx->rx_depth = cfg->rx_depth;
	ctx->buf_size = 2 * cfg->rx_depth * cfg->max_msg_size;
	ub_list_init(&ctx->dst_addr_list);
	
	ctx->buf = calloc(1, ctx->buf_size);
	if (!ctx->buf) {
		fprintf(stderr, "Failed to allocate recv buf.\n");
		goto clean_ctx;
	}
	ctx->send_buf = ctx->buf + cfg->rx_depth * cfg->max_msg_size;
	ctx->send_offset = 0;

	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) {
		fprintf(stderr, "Couldn't get context for %s\n", ibv_get_device_name(ib_dev));
		goto clean_buffer;
	}

	{
		struct ibv_port_attr port_info = {};
		int mtu;
		
		if (ibv_query_port(ctx->context, cfg->ib_port, &port_info)) {
			fprintf(stderr, "Unable to query port info for port %d\n", cfg->ib_port);
			goto clean_device;
		}
		mtu = 1 << (port_info.active_mtu + 7);
		if (cfg->max_msg_size > mtu) {
			fprintf(stderr, "Requested size larger than port MTU (%d)\n", mtu);
			goto clean_device;
		}
	}
	
	if (cfg->use_event) {
		ctx->channel = ibv_create_comp_channel(ctx->context);
		if (!ctx->channel) {
			fprintf(stderr, "Couldn't create completion channel\n");
			goto clean_device;
		}
	} else {
		ctx->channel = NULL;
	}
	
	ctx->pd = ibv_alloc_pd(ctx->context);
	if (!ctx->pd) {
		fprintf(stderr, "Couldn't allocate PD\n");
		goto clean_comp_channel;
	}
	
	/*ctx->mr = ibv_reg_mr(ctx->pd, ctx->buf, ctx->buf_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
	if (!ctx->mr) {
		fprintf(stderr, "Couldn't register MR\n");
		goto clean_pd;
	}*/
	
	ctx->cq = ibv_create_cq(ctx->context, cfg->rx_depth + 1, NULL, ctx->channel, 0);
	if (!ctx->cq) {
		fprintf(stderr, "Couldn't create CQ\n");
		goto clean_mr;
	}
	// create qp
	/*{
		struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init_attr = {
			.send_cq = ctx->cq,
			.recv_cq = ctx->cq,
			.cap = {
				.max_send_wr = 1,
				.max_recv_wr = cfg->rx_depth,
				.max_send_sge = 1,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_RC,
		};
		
		ctx->qp = ibv_create_qp(ctx->pd, &init_attr);
		if (!ctx->qp) {
			fprintf(stderr, "Couldn't create QP\n");
			goto clean_cq;
		}
		
		ibv_query_qp(ctx->qp, &attr, IBV_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= cfg->max_msg_size) {
			ctx->send_flags |= IBV_SEND_INLINE;
		}
	}*/

	// qp init
	/*{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = cfg->ib_port,
			.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE
		};

		if (ibv_modify_qp(ctx->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			goto clean_qp;
		}
	}*/
	
	return ctx;

clean_qp:
	ibv_destroy_qp(ctx->qp);

clean_cq:
	ibv_destroy_cq(ctx->cq);

clean_mr:
	ibv_dereg_mr(ctx->mr);

clean_pd:
	ibv_dealloc_pd(ctx->pd);

clean_comp_channel:
	if (ctx->channel)
		ibv_destroy_comp_channel(ctx->channel);

clean_device:
	ibv_close_device(ctx->context);

clean_buffer:
	free(ctx->buf);

clean_ctx:
	free(ctx);

	return NULL;
}

static int pkt_vm_rdma_get_local_addr(struct pkt_vm_rdma_context *ctx)
{
	struct rdma_transport_config *cfg = &ctx->cfg;
	
	if (ibv_query_port(ctx->context, cfg->ib_port, &ctx->portinfo)) {
		fprintf(stderr, "Couldn't get port info\n");
		return 1;
	}
	
	ctx->local_addr.lid = ctx->portinfo.lid;
	ctx->local_addr.qpn = ctx->qp->qp_num;
	ctx->local_addr.psn = lrand48() & 0xffffff;
	
	if (cfg->gid_index >= 0) {
		if (ibv_query_gid(ctx->context, cfg->ib_port, cfg->gid_index, &ctx->local_addr.gid)) {
			fprintf(stderr, "Couldn't get local gid for gid index %d\n", cfg->gid_index);
			return 1;
		}
	} else {
		memset(&ctx->local_addr.gid, 0, sizeof(ctx->local_addr.gid));
	}
	
	printf_rdma_addr_message(&ctx->local_addr);
	return 0;
	
}



static int pkt_vm_rdma_get_qp_msg(struct pkt_vm_rdma_context *ctx, struct rdma_addr_info *dst, int role)
{
	struct rdma_transport_config *cfg = &ctx->cfg;
	
	if (ibv_query_port(ctx->context, cfg->ib_port, &ctx->portinfo)) {
		fprintf(stderr, "Couldn't get port info\n");
		return 1;
	}
	
	if(!role) { // server: 0
		dst->local_recv_info.lid = ctx->portinfo.lid;
		dst->local_recv_info.qpn = dst->recv_qp->qp_num;
		dst->local_recv_info.psn = lrand48() & 0xffffff;
		
		if (cfg->gid_index >= 0) {
			if (ibv_query_gid(ctx->context, cfg->ib_port, cfg->gid_index, &dst->local_send_info.gid)) {
				fprintf(stderr, "Couldn't get local gid for gid index %d\n", cfg->gid_index);
				return 1;
			}
		} else {
			memset(&dst->local_send_info.gid, 0, sizeof(&dst->local_send_info.gid));
		}
		printf_rdma_addr_message(&dst->local_send_info);

	}else if (role) {	// client: 1
		dst->local_send_info.lid = ctx->portinfo.lid;
		dst->local_send_info.qpn = dst->send_qp->qp_num;
		dst->local_send_info.psn = lrand48() & 0xffffff;
		
		if (cfg->gid_index >= 0) {
			if (ibv_query_gid(ctx->context, cfg->ib_port, cfg->gid_index, &dst->local_send_info.gid)) {
				fprintf(stderr, "Couldn't get local gid for gid index %d\n", cfg->gid_index);
				return 1;
			}
		} else {
			memset(&dst->local_send_info.gid, 0, sizeof(&dst->local_send_info.gid));
		}
		printf_rdma_addr_message(&dst->local_send_info);
	}
	// printf_rdma_addr_message(&ctx->local_addr);
	return 0;
}

int pkt_vm_rdma_send(void *info, struct node_url *n, struct transport_message *msg)
{
	struct pkt_vm_rdma_context *ctx = info;
	struct rdma_addr_info *dst = pkt_vm_rdma_find_dest(ctx, n);
	struct ibv_sge list = {0};
	struct ibv_send_wr wr = {0};
	struct ibv_send_wr *bad_wr;
	
	if (msg->buf_size > ctx->cfg.max_msg_size) {
		printf("Message is too big to send.\n");
		return 0;
	}
	
	if (dst == NULL) {
		dst  = (struct rdma_addr_info *)malloc(sizeof(struct rdma_addr_info));
		// dst = pkt_vm_rdma_get_node_info(ctx, n);	// socket 发送端 (client)
		dst = pkt_vm_rdma_write_get_node_info(ctx, n, dst);	// socket 发送端 (client)
		// 得到了对端的信息，modify qp
		if (dst->if_send_init == 0){
			pkt_vm_init_after_socket(ctx, &dst->send_info, dst, 1);	// role: client
			// pkt_vm_rdma_enable_qp_rc(ctx, &dst->info);
			dst->if_send_init = 1;
		}
		if (dst == NULL) {
			perror("Failed to get destination information");
			return 0;
		}
	}
	// // 等待对端socket发送信息，然后利用信息修改 qp 
	// while (!if_receive);
	
	memcpy(dst->send_buf + dst->send_offset, msg->buf, msg->buf_size);
	
	// struct start_t_entry * t_entry = find_entry(ctx->start_table, 10, dst->info.remote_key);
	// // todo: 累加一下 t_entry 其中的 total, 然后放入立即数里
	// t_entry->r_mr_curr_total += msg->buf_size;
	list.addr = (uintptr_t)(dst->send_buf + dst->send_offset);
	list.length = msg->buf_size;
	list.lkey = dst->send_mr->lkey;
	
	wr.wr_id = (uint64_t)list.addr;
	wr.sg_list = &list;
	wr.num_sge = 1;
	wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
	// wr.send_flags = IBV_SEND_SIGNALED;
	wr.send_flags = ctx->send_flags;
	wr.wr.rdma.remote_addr = (uintptr_t)dst->send_info.mr_addr; // 远程 buffer 地址
	wr.wr.rdma.rkey = dst->send_info.remote_key;               // 远程 memory region 的 rkey
	wr.imm_data = (u_int32_t)msg->buf_size; // 传输立即数

	// wr.wr.ud.ah = dst->ah;
	// wr.wr.ud.remote_qpn = dst->info.qpn;
	// wr.wr.ud.remote_qkey = 0x11111111;
	
	if (ibv_post_send(dst->send_qp, &wr, &bad_wr) == 0) {
		dst->send_offset = (dst->send_offset + ctx->cfg.max_msg_size) % (ctx->cfg.max_msg_size * ctx->cfg.rx_depth);
		return msg->buf_size;
	} else {
		return 0;
	}
}

// 其实write并不需要recv，但是with immediate 需要轮询recv，然后在业务层去处理这个立即数
int pkt_vm_rdma_write_recv(void *info, struct transport_message *msg)
{
	struct pkt_vm_rdma_context *ctx = info;
	struct ibv_wc wc;
	
	if (ibv_poll_cq(ctx->cq, 1, &wc) <= 0) {
		return 0;
	}
	
	if (wc.status != IBV_WC_SUCCESS) {
		printf("wc failure status = %d.\n", wc.status);
		printf("wc failure opcode = %d.\n", wc.opcode);
		return 0;
	}
	
	// if (wc.opcode != IBV_WC_RECV) {
	// 	if (wc.opcode != IBV_WC_SEND) {
	// 		printf("wc failure opcode = %d.\n", wc.opcode);
	// 	}
	// 	return 0;
	// }
	
	uint32_t imm_data;
	// 检查是否成功接收到 RDMA Write with Immediate 的完成通知
	if (wc.status == IBV_WC_SUCCESS && wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
		// if (wc.status == IBV_WC_SUCCESS || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
		// 获取立即数，并将其从网络字节序转换为主机字节序
		imm_data = wc.imm_data;
		printf("Received immediate data: 0x%x\n", imm_data);
	}else if (wc.opcode == IBV_WC_RDMA_WRITE){
		printf("Have writen data to remote\n");
		return 0;
	}
	else {
		fprintf(stderr, "Failed to receive immediate data or wrong opcode\n");
	}
	// imm_data
	// 把数据放进msg中去 
	// msg->buf_size = (uintptr_t)ctx->mr->addr - (uintptr_t)imm_data;	
	// memcpy(ctx->mr->addr, msg->buf, msg->buf_size);
	msg->buf_size = (int)imm_data;
	memcpy(msg->buf, ctx->mr->addr, msg->buf_size);
	// msg->buf = (void *)((char *)wc.wr_id);
	// msg->buf_size = wc.byte_len;
	return (int)imm_data;
}

int pkt_vm_rdma_recv(void *info, struct transport_message *msg)
{
	struct pkt_vm_rdma_context *ctx = info;
	struct ibv_wc wc;
	
	if (ibv_poll_cq(ctx->cq, 1, &wc) <= 0) {
		return 0;
	}
	
	if (wc.status != IBV_WC_SUCCESS) {
		printf("wc failure status = %d.\n", wc.status);
		return 0;
	}
	
	if (wc.opcode != IBV_WC_RECV) {
		if (wc.opcode != IBV_WC_SEND) {
			printf("wc failure opcode = %d.\n", wc.opcode);
		}
		
		return 0;
	}

	msg->buf = (void *)((char *)wc.wr_id);
	msg->buf_size = wc.byte_len;
	
	return msg->buf_size;
}

static void pkt_vm_rdma_return_buf(void *info, struct transport_message *msg)
{
	// pkt_vm_rdma_post_recv(info, msg->buf);
}

static void pkt_vm_rdma_exit(void *info)
{
	struct pkt_vm_rdma_context *ctx = info;
	struct rdma_addr_info *dst, *tmp;
	
	if (ctx->server_thread != (pthread_t)0) {
		ctx->state.should_stop = 1;
		pthread_join(ctx->server_thread, NULL);
	}
	
	if (ibv_destroy_qp(ctx->qp)) {
		fprintf(stderr, "Couldn't destroy OP\n");
		return;
	}
	
	if (ibv_destroy_cq(ctx->cq)) {
		fprintf(stderr, "Couldn't destroy CQ\n");
		return;
	}
	
	if (ibv_dereg_mr(ctx->mr)) {
		fprintf(stderr, "Couldn't deregister MR\n");
		return;
	}
	
	UB_LIST_FOR_EACH_SAFE(dst, tmp, node, &ctx->dst_addr_list) {
		ub_list_remove(&dst->node);

		if (ibv_destroy_ah(dst->ah)) {
			perror("Couldn't destroy AH");
		}

		free(dst);
	}
	
	if (ibv_dealloc_pd(ctx->pd)) {
		fprintf(stderr, "Couldn't deallocate PD");
		return;
	}
	
	if (ctx->channel) {
		if (ibv_destroy_comp_channel(ctx->channel)) {
			fprintf(stderr, "Couldn't destroy completion channel\n");
			return;
		}
	}
	
	if (ibv_close_device(ctx->context)) {
		fprintf(stderr, "Couldn't release context\n");
		return;
	}
	
	free(ctx->buf);
	free(ctx);
}

static void *pkt_vm_rdma_init(struct transport_config *cfg)
{
	struct pkt_vm_rdma_context *ctx = NULL;
	int idx, ret;
	
	srand48(getpid() * time(NULL));
	
	ctx = pkt_vm_rdma_init_ctx(&cfg->rdma_cfg);		// 建链
	if (ctx == NULL) {
		printf("Failed to create rdma context.\n");
		return NULL;
	}
	
	// 不需要receive
	// for (idx = 0; idx < cfg->rdma_cfg.rx_depth; idx++) {
	// 	ret = pkt_vm_rdma_post_recv(ctx, (ctx->buf + (idx * cfg->rdma_cfg.max_msg_size)));
	// 	if (ret != 0) {
	// 		perror("Failed to post recv buffer");
	// 	}
	// }
	
	pkt_vm_rdma_get_local_addr(ctx);	// 现在这个方法不合适，需要对每个dst内的qp分别保存信息
	// 作为代替的是 `pkt_vm_rdma_get_qp_msg`，因为本地有多个qp，所以qpn有多个，所以要在rdma_addr_info里面保存每个qp对应的local info
	ret = pthread_create(&ctx->server_thread, NULL, pkt_vm_rdma_server_main, ctx);	// 每个机子都自身为服务器 (server)

	if (ret != 0) {
		perror("Failed to create server thread");
		pkt_vm_rdma_exit(ctx);
		return NULL;
	}
	
	// pkt_vm_rdma_enable_qp(ctx);
	return ctx;
}

// static struct transport_ops rdma_ops = {
// 	.type = PKT_VM_TRANSPORT_TYPE_RDMA,
// 	.init = pkt_vm_rdma_init,
// 	.exit = pkt_vm_rdma_exit,
// 	.send = pkt_vm_rdma_send,
// 	.recv = pkt_vm_rdma_recv,
// 	.return_buf = pkt_vm_rdma_return_buf,
// };



static struct transport_ops rdma_ops = {
	.type = PKT_VM_TRANSPORT_TYPE_RDMA,
	.init = pkt_vm_rdma_init,
	.exit = pkt_vm_rdma_exit,
	.send = pkt_vm_rdma_send,
	.recv = pkt_vm_rdma_write_recv,
	.return_buf = pkt_vm_rdma_return_buf,
};


static __attribute__((constructor)) void pkt_vm_rdma_register_transport(void)
{
	register_transport(&rdma_ops);
}