#include <actor.h>
#include <linux/printk.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

static actor_t* send;
static actor_t* recv[2];

int ct_send_func(actor_t* self, actor_work_t* aw) {
	int i;

	pr_notice("Sending... aw_flags = %llx msg = %p\n", aw->aw_flags, aw->aw_msg);

	for(i = 0; i < 2; ++i)
		actor_communicate_blocked(recv[i], aw->aw_msg);

	return ACTOR_INCOMPLETE;
}

int ct_send_func2(actor_t* self, actor_work_t* aw) {
	pr_notice("Sending finished aw_flags = %llx msg = %p\n", aw->aw_flags, aw->aw_msg);

	if(aw->aw_comm_count) {
		return ACTOR_INCOMPLETE_STAGE;
	}

	return ACTOR_SUCCESS;
}

static DECLARE_ACTOR_EXEC(ct_send_exec, ct_send_func, ct_send_func2);

int ct_recv_func(actor_t* self, actor_work_t* aw) {
	pr_notice("Receiving... aw_flags = %llx msg = %p\n", aw->aw_flags, aw->aw_msg);

	return ACTOR_SUCCESS;
}

static DECLARE_ACTOR_EXEC(ct_recv_exec, ct_recv_func);

int commtest_init(void) {
	int nodeid = 0;
	int i = 0;

	amsg_hdr_t* msg = amsg_create(0, 0, NULL, nodeid);

	send = actor_create_simple(0, 0, nodeid++, "send", &ct_send_exec);
	for(i = 0; i < 2; ++i)
		recv[i] = actor_create_simple(0, 0, nodeid + i, "recv", &ct_recv_exec);

	for(i = 0; i < 5; ++i) {
		actor_communicate_blocked(send, msg);

		printk("Communication step #%d\n", i);
	}

	return 0;
}

void commtest_exit(void) {
	int i = 0;

	actor_destroy(send);

	for(i = 0; i < 2; ++i)
		actor_destroy(recv[i]);
}

module_init(commtest_init);
module_exit(commtest_exit);
