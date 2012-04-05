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
#include <linux/mutex.h>
#include <linux/string.h>
#include <asm/uaccess.h>

struct benchmark;

MODULE_LICENSE("GPL");

/**********************
 * ACTOR
 **********************/
typedef struct actor_bench_private {
	volatile long i;
	volatile int is_done;
} actor_bench_priv_t;

static actor_t* test_actor;

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
	actor_bench_priv_t* abp = (actor_bench_priv_t*) self->a_private;

	abp->i++;

	return abp->is_done;

	// return ACTOR_SUCCESS;
}

void actor_init(void) {
	test_actor = actor_create(0, 0, smp_processor_id(),
								"test", actor_test_ctor, actor_test_dtor,
								actor_test_callback);
}

void actor_deinit(void) {
	actor_destroy(test_actor);
}

int actor_bench(struct benchmark* b, void* data) {
	amsg_hdr_t* msg = amsg_create(0, 0, test_actor->a_nodeid);

	/*Message is freed on actor-side*/
	return actor_communicate(test_actor, msg, 1);
}

long actor_bench_results(struct benchmark* b) {
	actor_bench_priv_t* abp;

	abp = (actor_bench_priv_t*) test_actor->a_private;
	abp->is_done = ACTOR_SUCCESS;

	return abp->i;
}

/**********************
 * MULTIPLE ACTORS
 **********************/

static actor_t* test_multi_actor[NR_CPUS];

void multi_actor_init(void) {
	int i;

	for_each_online_cpu(i) {
		test_multi_actor[i] =
				actor_create(0, 0, i, "multi",
							actor_test_ctor,
							actor_test_dtor,
							actor_test_callback);
	}
}

void multi_actor_deinit(void) {
	int i;

	for_each_online_cpu(i) {
		actor_destroy(test_multi_actor[i]);
	}
}

int multi_actor_bench(struct benchmark* b, void* data) {
	int nodeid = smp_processor_id();
	actor_t* ac = test_multi_actor[nodeid];

	amsg_hdr_t* msg = amsg_create(0, 0, nodeid);

	/*Message is freed on actor-side*/
	return actor_communicate(ac, msg, 1);
}

long multi_actor_bench_results(struct benchmark* b) {
	actor_bench_priv_t* abp;
	long result = 0;
	int i;

	for_each_online_cpu(i) {
		abp = (actor_bench_priv_t*) test_multi_actor[i]->a_private;
		abp->is_done = ACTOR_SUCCESS;

		result += abp->i;
	}

	return result;
}

/**********************
 * ATOMIC
 **********************/
static atomic_t test_atom;

int atomic_bench(struct benchmark* b, void* data) {
	atomic_inc(&test_atom);

	return 0;
}

long atomic_bench_results(struct benchmark* b) {
	return atomic_read(&test_atom);
}


/********************
 * SPINLOCK
 ********************/
static long test_sl = 0;
static DEFINE_SPINLOCK(test_lock);

int spinlock_bench(struct benchmark* b, void* data) {
	unsigned long flags = 0;

	spin_lock_irqsave(&test_lock, flags);
	test_sl++;
	spin_unlock_irqrestore(&test_lock, flags);

	return 0;
}

long spinlock_bench_results(struct benchmark* b) {
	return test_sl;
}

/********************
 * MUTEX
 ********************/

static long test_mtx = 0;
static DEFINE_MUTEX(test_mutex);

int mutex_bench(struct benchmark* b, void* data) {
	mutex_lock(&test_mutex);
	test_mtx++;
	mutex_unlock(&test_mutex);

	return 0;
}

long mutex_bench_results(struct benchmark* b) {
	return test_mtx;
}

/********************
 * MAIN BENCHMARK ROUTINES
 ********************/
typedef enum bench_stage {
	BENCH_NONE = -1,
	BENCH_ACTOR,
	BENCH_MULTI_ACTOR,
	BENCH_ATOMIC,
	BENCH_SPIN,
	BENCH_MUTEX,
	BENCH_DONE
} bench_stage_t;

struct benchmark {
	const char* name;

	int (*bench_func)(struct benchmark*, void* );
	long (*bench_get_results)(struct benchmark* );
};

#define BENCH_DURATION 60

static volatile bench_stage_t benchmark_stage = BENCH_NONE;
static struct timer_list bench_timer;

struct task_struct* bench_threads[NR_CPUS] = {NULL};

struct proc_dir_entry* test_proc_entry;

#define BENCHMARK(bname)				\
	{									\
		.name = #bname , 				\
		.bench_func = bname ## _bench,	\
		.bench_get_results =			\
			bname ## _bench_results		\
	}

struct benchmark benchmarks[] =
{
	BENCHMARK(actor),
	BENCHMARK(multi_actor),
	BENCHMARK(atomic),
	BENCHMARK(spinlock),
	BENCHMARK(mutex)
};

void set_benchmark_stage(int new_stage) {
	if(new_stage < BENCH_DONE && new_stage > BENCH_NONE) {
		printk("Benchmarking '%s'...", benchmarks[new_stage].name);

		benchmark_stage = new_stage;

		mod_timer(&bench_timer, jiffies + HZ * BENCH_DURATION);
	}
}

void benchmark_timer_func(unsigned long data) {
	struct benchmark* finished = benchmarks + benchmark_stage;

	if(benchmark_stage == BENCH_DONE)
		return;

	printk(KERN_INFO "Results for '%s' are: %ld incs / %ds\n",
					finished->name, finished->bench_get_results(finished), BENCH_DURATION);

	benchmark_stage = BENCH_DONE;
}

int benchmark_thread(void* data) {
	struct benchmark* benchmark = NULL;

	while(benchmark_stage != BENCH_DONE) {
		benchmark = benchmarks + benchmark_stage;
		benchmark->bench_func(benchmark, data);
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
	case BENCH_DONE: return snprintf(page, count, "done\n");
	default: return snprintf(page, count, "%s\n", benchmarks[benchmark_stage].name);
	}

	/*NOTREACHED*/
	return 0;
}

int test_proc_write(struct file *file, const char *buffer, unsigned long count, void *data) {
	int i = 0;
	int new_stage;

	char new_stage_name[32];

	if(benchmark_stage != BENCH_DONE &&
			benchmark_stage != BENCH_NONE)
		return -EBUSY;

	if(count > 32)
		return -EINVAL;

	if(copy_from_user(new_stage_name, buffer, count))
		return -EINVAL;
	new_stage_name[count] = '\0';

	/*Detect which benchmark we want*/
	for(new_stage = BENCH_NONE + 1;
		new_stage < BENCH_DONE;
		new_stage++) {

		if(strcmp(benchmarks[new_stage].name, new_stage_name) == 0)
			break;
	}

	if(new_stage == BENCH_DONE)
		return -EINVAL;

	set_benchmark_stage(new_stage);

	for_each_online_cpu(i) {
		bench_threads[i] = kthread_create(benchmark_thread, NULL, "bench-%d", i);
		wake_up_process(bench_threads[i]);
	}

	return count;
}

int benchmark_init(void) {
	actor_init();
	multi_actor_init();
	
	if(IS_ERR(test_actor))
		return PTR_ERR(test_actor);


	init_timer(&bench_timer);
	setup_timer(&bench_timer, benchmark_timer_func, 0);


	test_proc_entry = create_proc_entry("actor_bench", 0600, NULL);
	test_proc_entry->read_proc = test_proc_read;
	test_proc_entry->write_proc = test_proc_write;

	return 0;
}

void benchmark_exit(void) {
	int i;

	remove_proc_entry("actor_bench", NULL);

	/* for_each_online_cpu(i) {
		kthread_stop(bench_threads[i]);
	} */

	del_timer(&bench_timer);

	actor_deinit();
	multi_actor_deinit();
}

module_init(benchmark_init);
module_exit(benchmark_exit);
