#include <actor.h>
#include <linux/printk.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

static actor_t* send;
static actor_t* recv;

int ct_send_func(actor_t* self, amsg_hdr_t* msg, int aw_flags) {
	pr_notice("Sending... aw_flags = %x msg = %p\n", aw_flags, msg);

	if(aw_flags & AW_COMM_COMPLETE)
		return ACTOR_SUCCESS;

	actor_communicate_blocked(recv, msg);

	return ACTOR_SUCCESS;
}

int ct_recv_func(actor_t* self, amsg_hdr_t* msg, int aw_flags) {
	pr_notice("Receiving... aw_flags = %x msg = %p\n", aw_flags, msg);

	return ACTOR_SUCCESS;
}

int commtest_init(void) {
	int nodeid = 0;
	int i = 0;

	amsg_hdr_t* msg = amsg_create(0, 0, nodeid);

	send = actor_create_simple(0, 0, nodeid, "send", ct_send_func);
	recv = actor_create_simple(0, 0, nodeid, "recv", ct_recv_func);

	for(i = 0; i < 5; ++i) {
		actor_communicate_blocked(send, msg);

		printk("Communication step #%d\n", i);
	}

	return 0;
}

void commtest_exit(void) {
	actor_destroy(send);
	actor_destroy(recv);
}

module_init(commtest_init);
module_exit(commtest_exit);
