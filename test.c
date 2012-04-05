#include <actor.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/timer.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>

/*actor data*/
static actor_t* test_actor;

/*atomic data*/
static atomic_t test_atom;

/*spinlock data*/
static int test_sl = 0;
static DEFINE_SPINLOCK(test_lock);

#define BENCH_NONE 0
#define BENCH_ACTOR 1
#define BENCH_ATOMIC 2
#define BENCH_SPIN 3
#define BENCH_DONE 4

#define BENCH_DURATION 10

static volatile int benchmark_stage;		/*0 - no benchmarking, 1 - actor, 2 - atomic, 3 - spinlock, 4 - done*/
static struct timer_list bench_timer;

struct task_struct* bench_threads[NR_CPUS] = {NULL};

struct proc_dir_entry* test_proc_entry;

typedef struct actor_bench_private {
	volatile int i;
	volatile int is_done;
} actor_bench_priv_t;

int actor_init(void);
int actor_free(void);

MODULE_LICENSE("GPL");

void _set_benchmark_stage(int stage) {
	printk(KERN_INFO "Benchmark stage set to %d", stage);

	benchmark_stage = stage;
}

int actor_test_ctor(actor_t* self) {
	actor_bench_priv_t* abp = (actor_bench_priv_t*)
			actor_private_allocate(self, sizeof(actor_bench_priv_t));

	abp->i = 0;
	abp->is_done = ACTOR_INCOMPLETE;

	self->a_private = abp;

	return 0;
}

int actor_test_dtor(actor_t* self) {
	actor_private_free(self);

	return 0;
}

int actor_test_callback(actor_t* self, amsg_hdr_t* msg) {
	/* printk(KERN_INFO "Received message u:%ld t:%ld\n",
	  AMSG_UNTYPED_NUM(msg),
	  AMSG_TYPED_NUM(msg)
	); */
	
	actor_bench_priv_t* abp = (actor_bench_priv_t*) self->a_private;

	abp->i++;

	// return abp->is_done;

	return 0;
}

void benchmark_timer_func(unsigned long data) {
	actor_bench_priv_t* abp;

	switch(benchmark_stage) {
	case BENCH_ACTOR:
		_set_benchmark_stage(BENCH_ATOMIC);

		abp = (actor_bench_priv_t*) test_actor->a_private;
		abp->is_done = ACTOR_SUCCESS;

		printk(KERN_INFO "Results for actors are: %d incs / %ds\n",
					abp->i, BENCH_DURATION);

		mod_timer(&bench_timer, jiffies + HZ * BENCH_DURATION);
	break;
	case BENCH_ATOMIC:
		_set_benchmark_stage(BENCH_SPIN);

		printk(KERN_INFO "Results for atomics are: %d incs / %ds\n",
				atomic_read(&test_atom), BENCH_DURATION);

		mod_timer(&bench_timer, jiffies + HZ * BENCH_DURATION);
	break;
	case BENCH_SPIN:
		_set_benchmark_stage(BENCH_DONE);

		printk(KERN_INFO "Results for spinlocks are: %d incs / %ds\n",
				test_sl, BENCH_DURATION);
	break;
	}
}

int benchmark_thread(void* data) {
	actor_t* _test_actor = test_actor;
	amsg_hdr_t* msg = (amsg_hdr_t*) data;

	while(benchmark_stage == BENCH_NONE) {
		rmb();
	}

	printk(KERN_INFO "Benchmarking actors...");

	while(benchmark_stage == BENCH_ACTOR) {
		actor_communicate(_test_actor, msg, 1);
	}

	printk(KERN_INFO "Benchmarking atomics...");

	while(benchmark_stage == BENCH_ATOMIC) {
		atomic_inc(&test_atom);
	}

	printk(KERN_INFO "Benchmarking spinlocks...");

	while(benchmark_stage == BENCH_SPIN) {
		unsigned long flags = 0;

		spin_lock_irqsave(&test_lock, flags);
		test_sl++;
		spin_unlock_irqrestore(&test_lock, flags);
	}

	return 0;
}

int test_proc_read(char* page, char** start, off_t off, int count, int* eof, void* data) {
	if(off > 0) {
		*eof = 1;
		return 0;
	}

	*start = page + off;

	switch(benchmark_stage) {
	case BENCH_NONE: return snprintf(page, count, "none\n");
	case BENCH_ACTOR: return snprintf(page, count, "actor\n");
	case BENCH_ATOMIC: return snprintf(page, count, "atomic\n");
	case BENCH_SPIN: return snprintf(page, count, "spin\n");
	case BENCH_DONE: return snprintf(page, count, "done\n");
	default: strncpy(page, "???", count);
	}

	return 0;
}

int test_proc_write(struct file *file, const char *buffer, unsigned long count, void *data) {
	int i = 0;

	if(benchmark_stage == BENCH_NONE || benchmark_stage == BENCH_DONE) {
		/*Reset benchmark*/
		mod_timer(&bench_timer, jiffies + HZ * 10);
		_set_benchmark_stage(BENCH_ACTOR);

		for_each_online_cpu(i) {
			wake_up_process(bench_threads[i]);
		}

		return count;
	}

	return -EINVAL;
}

int actor_test_init(void) {
	int i = 0;
	amsg_hdr_t* msg;

	test_actor = actor_create(0, 0, smp_processor_id(), 
							"test", actor_test_ctor, actor_test_dtor,
							actor_test_callback);
	
	if(IS_ERR(test_actor))
		return PTR_ERR(test_actor);

	_set_benchmark_stage(BENCH_NONE);

	init_timer(&bench_timer);
	setup_timer(&bench_timer, benchmark_timer_func, 0);

	for_each_online_cpu(i) {
		msg = amsg_create(0, 0, test_actor->a_nodeid);

		bench_threads[i] = kthread_create(benchmark_thread, msg, "bench-%d", i);
	}

	test_proc_entry = create_proc_entry("actor_bench", 0600, NULL);
	test_proc_entry->read_proc = test_proc_read;
	test_proc_entry->write_proc = test_proc_write;

	return 0;
}



void actor_test_exit(void) {
	int i;

	remove_proc_entry("actor_bench", NULL);

	/* for_each_online_cpu(i) {
		kthread_stop(bench_threads[i]);
	} */

	del_timer(&bench_timer);

	actor_destroy(test_actor);
}

module_init(actor_test_init);
module_exit(actor_test_exit);
