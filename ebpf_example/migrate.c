#include <stdint.h>
#include <stddef.h>
#include <ebpf_vm_functions.h>
#include <stdlib.h>
#include <stdio.h>

void test_migrate(struct ub_address *a1, struct ub_address *a2, struct ub_address *b1, struct ub_address *b2, int cnt)
{
	uint64_t msg = 1000;
	int idx;
	
	for (idx = 0; idx < cnt; idx++) {
		debug_print(msg);
		msg += 1000;
		migrate_to(b2);
		
		debug_print(msg);
		msg += 1000;
		migrate_to(a1);

		debug_print(msg);
		msg += 1000;
		migrate_to(a2);

		debug_print(msg);
		msg += 1000;
		migrate_to(b1);
	}
}

uint64_t vm_main(void)
{

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


	/* Migrate to 1.1.8.78:1881 */
	test_migrate(&a1, &a2, &b1, &b2, 20);

	
	return 0;
}