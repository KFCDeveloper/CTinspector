#include <stdint.h>
#include <stddef.h>
#include <ebpf_vm_functions.h>
#include <stdlib.h>
#include <stdio.h>

void test_migrate(struct ub_address * addrs, int n, int cnt)
{
	uint64_t msg = 10;
	int idx;
	
	for (size_t i = 0, j = 0; j < cnt; j++)
	{
		debug_print(msg);
		msg += 10;
		migrate_to(&addrs[i]);	// 所以在这里可以看出来，是 index=3（第四台）先发送消息
		i = (i + 1) % n;
	}
}

// void test_migrate(struct ub_address *a, struct ub_address *b, int cnt)
// {
// 	uint64_t msg = 10;
// 	int idx;
	
// 	for (idx = 0; idx < cnt; idx++) {
// 		debug_print(msg);
// 		msg += 10;
// 		migrate_to(a);
		
// 		debug_print(msg);
// 		msg += 10;
// 		migrate_to(b);
// 	}
// }

uint64_t vm_main(void)
{
	int n = 4; // vm 经过4个运行端
	int m = 20; // vm 的传输跳数

	// 创建 url 数组; 动态分配数组的内存，用于存储结构体
    struct ub_address *addrs = (struct ub_address *)malloc(n * sizeof(struct ub_address));

    if (addrs == NULL) {
        printf("内存分配失败\n");
        return 1;
    }

	struct ub_address a1 = {
		.access_key = 0,
		.url = {192, 168, 25, 128, 7, 88}
	};

	struct ub_address a2 = {
		.access_key = 0,
		.url = {192, 168, 25, 128, 7, 89}
	};

	struct ub_address b1 = {
		.access_key = 0,
		.url = {192, 168, 25, 129, 7, 88} // 1880
	};
	
	struct ub_address b2 = {
		.access_key = 0,
		.url = {192, 168, 25, 129, 7, 89} // 1881
	};

	// 将 a 和 b 赋值给 addrs 数组的第一个和第二个元素
    addrs[0] = a1;
    addrs[1] = b1;
	addrs[2] = a2;
    addrs[3] = b2;

	test_migrate(addrs, n, m);

	/* Migrate to 1.1.8.78:1881 */
	// test_migrate(&a, &b, 20);
	
	return 0;
}