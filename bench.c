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
#include <linux/cpumask.h>
#include <linux/percpu.h>

struct benchmark;

MODULE_LICENSE("GPL");

/*#####################
 * Critical section benchmark
 *#####################*/

/**********************
 * ACTOR
 **********************/
typedef struct actor_bench_private {
	volatile long i;
	volatile int is_done;
} actor_bench_priv_t;

static actor_t* test_actor;

int actor_test_callback(actor_t* self, actor_work_t* aw) {
	actor_bench_priv_t* abp = (actor_bench_priv_t*) self->a_private;

	abp->i++;

// return abp->is_done;
	return ACTOR_SUCCESS;
}

static DECLARE_ACTOR_EXEC(actor_test_exec, actor_test_callback);

int actor_test_ctor(actor_t* self, void* data) {
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

int actor_init(void) {
	test_actor = actor_create(0, 0, smp_processor_id(),
								"test", actor_test_ctor, actor_test_dtor,
								&actor_test_exec, NULL);

	return 0;
}

int actor_deinit(void) {
	actor_destroy(test_actor);

	return 0;
}

int actor_bench(struct benchmark* b, void* data) {
	amsg_hdr_t* msg = amsg_create(0, 0, NULL, test_actor->a_nodeid);

	/*Message is freed on actor-side*/
	return actor_communicate_async(test_actor, msg);
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

int multi_actor_init(void) {
	int i;

	for_each_online_cpu(i) {
		test_multi_actor[i] =
				actor_create(0, 0, i, "multi",
							actor_test_ctor,
							actor_test_dtor,
							&actor_test_exec,
							NULL);
	}

	return 0;
}

int multi_actor_deinit(void) {
	int i;

	for_each_online_cpu(i) {
		actor_destroy(test_multi_actor[i]);
	}

	return 0;
}

int multi_actor_bench(struct benchmark* b, void* data) {
	int nodeid = smp_processor_id();
	actor_t* ac = test_multi_actor[nodeid];

	amsg_hdr_t* msg = amsg_create(0, 0, NULL, nodeid);

	/*Message is freed on actor-side*/
	return actor_communicate_async(ac, msg);
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
 * PER_CPU
 ********************/

static DEFINE_PER_CPU(long, test_percpu);

int percpu_bench(struct benchmark* b, void* data) {
	percpu_add(test_percpu, 1);

	return 0;
}

long percpu_bench_results(struct benchmark* b) {
	int i = 0;
	long res = 0;

	for_each_online_node(i) {
		res += per_cpu(test_percpu, i);
	}

	return res;
}


/*#######################
 *  Ping-Pong Benchmark
 *#######################*/

static unsigned int num_clients = 32;
module_param(num_clients, uint, S_IRWXU);
#define NUM_CLIENTS num_clients

static unsigned int num_domains = 8;
module_param(num_domains, uint, S_IRWXU);
#define NUM_DOMAINS num_domains

/********************
 * ACTOR
 ********************/

static atomic_t pp_actor_score;

int pp_actor_is_done = 1;

static actor_t** pp_actors;

struct pp_actor_priv {
	actor_t* next;
};

int pp_actor_med_ctor(actor_t* self, void* data) {
	struct pp_actor_priv* p =
			actor_private_allocate(self, sizeof(struct pp_actor_priv));

	p->next = (actor_t*) data;

	return 0;
}

int pp_actor_med_cb(actor_t* ac, actor_work_t* aw) {
	/*Send message to */
	struct pp_actor_priv* p = (struct pp_actor_priv*) ac->a_private;
	
	/*Forward message to next actor*/
	actor_communicate_blocked(p->next, aw->aw_msg);

	return ACTOR_INCOMPLETE;
}

int pp_actor_med_cb2(actor_t* ac, actor_work_t* aw) {
	return ACTOR_SUCCESS;
}

static DECLARE_ACTOR_EXEC(pp_actor_med_exec, pp_actor_med_cb, pp_actor_med_cb2);

int pp_actor_last_cb(actor_t* ac, amsg_hdr_t* msg, int aw_flags) {
	/*Last actor in chain simply returns success*/
	atomic_inc(&pp_actor_score);

	return ACTOR_SUCCESS;
}

static DECLARE_ACTOR_EXEC(pp_actor_last_exec, pp_actor_last_cb);

int pp_actor_init(void) {
	int ai = NUM_DOMAINS - 1;
	int nodeid = smp_processor_id();
	actor_t* prev = NULL;

	pp_actors = kmalloc(sizeof(actor_t*) * num_domains, GFP_KERNEL);

	//Last actor in chain
	prev = actor_create(0, 0, nodeid, "pp_last", NULL, NULL, &pp_actor_last_exec, NULL);
	pp_actors[ai--] = prev;

	pp_actor_is_done = 0;

	for(; ai >= 0; --ai) {
		nodeid = cpumask_next(nodeid, cpu_online_mask);

		if(nodeid >= nr_cpu_ids)
			nodeid = cpumask_first(cpu_online_mask);

		prev = actor_create(0, 0, nodeid, "pp_med",
							pp_actor_med_ctor,
							NULL,
							&pp_actor_med_exec, (void*) prev);
		pp_actors[ai] = prev;
	}

	return 0;
}

int pp_actor_deinit(void) {
	int ai;

	for(ai = 0; ai < NUM_DOMAINS; ++ai)
		actor_destroy(pp_actors[ai]);

	kfree(pp_actors);

	return 0;
}

int pp_actor_bench(struct benchmark* b, void* data) {
	/*Send message to first actor and wait*/
	amsg_hdr_t* msg = amsg_create(0, 0, NULL, smp_processor_id());

	actor_communicate_blocked(pp_actors[0], msg);

	return 0;
}

long pp_actor_bench_results(struct benchmark* b) {
	pp_actor_is_done = 1;

	return atomic_read(&pp_actor_score);
}

/********************
 * THREAD
 ********************/

static long pp_thread_score = 0;

int pp_thread_is_done = 1;

struct pp_thread_message {
	struct list_head list;
	struct completion com;
};

static struct pp_thread_struct {
	struct task_struct* kthread;
	struct pp_thread_struct* next;

	struct list_head queue;
	struct mutex lock;
} *pp_threads;

void pp_thread_forward(struct list_head* l, struct pp_thread_struct* next) {
	list_del(l);

	mutex_lock(&next->lock);
	list_add_tail(l, &next->queue);
	mutex_unlock(&next->lock);
}

int pp_thread_complete(struct list_head* q) {
    struct list_head* l = NULL, *ln = NULL;
    struct pp_thread_message* msg = NULL;    
    int n = 0;
    
    list_for_each_safe(l, ln, q) {
        msg = (struct pp_thread_message*) list_entry(l, struct pp_thread_message, list);

        list_del(l);
        complete(&msg->com);

        ++n;
    }
    
    return n;
}

int pp_thread_med(void* data) {
	// transfer to next thread
	struct list_head* l = NULL, *ln = NULL;

	struct pp_thread_struct* thr = (struct pp_thread_struct*) data;
	struct pp_thread_struct* next = thr->next;

    struct list_head actq;
    
	while(!pp_thread_is_done) {
        INIT_LIST_HEAD(&actq);
        
        /*Switch queues*/
		mutex_lock(&thr->lock);
        list_splice_init(&thr->queue, &actq);
        mutex_unlock(&thr->lock);
        
		list_for_each_safe(l, ln, &actq) {
			pp_thread_forward(l, next);
		}

		wake_up_process(next->kthread);
        
		might_sleep();
	}

	pp_thread_complete(&thr->queue);
	
	return 0;
}

int pp_thread_last(void* data) {
	struct pp_thread_struct* thr = (struct pp_thread_struct*) data;
    
	while(!pp_thread_is_done) {
		mutex_lock(&thr->lock);
        pp_thread_score += pp_thread_complete(&thr->queue);
		mutex_unlock(&thr->lock);

		//Sleep
		might_sleep();
	}

	pp_thread_complete(&thr->queue);
	
	return 0;
}

int pp_thread_init(void) {
	int ti = NUM_DOMAINS - 1;

	pp_thread_is_done = 0;

	pp_threads = kmalloc(sizeof(struct pp_thread_struct) * num_domains, GFP_KERNEL);

	for(; ti >= 0; --ti) {
		mutex_init(&(pp_threads[ti].lock));
		INIT_LIST_HEAD(&(pp_threads[ti].queue));

		pp_threads[ti].kthread = kthread_create((ti == NUM_DOMAINS - 1) ? pp_thread_last : pp_thread_med,
								(void*) (pp_threads + ti), "ppthread-%d", ti);
		pp_threads[ti].next = (ti == NUM_DOMAINS - 1) ? NULL : pp_threads + ti + 1;
	}

	return 0;
}

int pp_thread_deinit(void) {
	return 0;
}

int pp_thread_bench(struct benchmark* b, void* data) {
	/*Send message to first actor and wait*/
	struct pp_thread_message msg;
	struct pp_thread_struct* thr = &pp_threads[0];

	INIT_LIST_HEAD(&msg.list);
	init_completion(&msg.com);

	mutex_lock(&thr->lock);
	list_add_tail(&msg.list, &thr->queue);
	mutex_unlock(&thr->lock);

	wake_up_process(thr->kthread);
	wait_for_completion(&msg.com);

	return 0;
}

long pp_thread_bench_results(struct benchmark* b) {
	pp_thread_is_done = 1;

	return pp_thread_score;
}

/*#######################
 *  Main module
 *#######################*/

typedef enum bench_stage {
	BENCH_NONE = -1,
	BENCH_ACTOR,
	BENCH_MULTI_ACTOR,
	BENCH_ATOMIC,
	BENCH_SPIN,
	BENCH_MUTEX,
	BENCH_PP_ACTOR,
	BENCH_PP_THREAD,
	BENCH_DONE
} bench_stage_t;

struct benchmark {
	const char* name;

	int (*bench_init)(void);
	int (*bench_deinit)(void);

	int (*bench_func)(struct benchmark*, void* );
	long (*bench_get_results)(struct benchmark* );
};

#define BENCH_DURATION 10

static volatile bench_stage_t benchmark_stage = BENCH_NONE;
static struct timer_list bench_timer;

struct task_struct** bench_threads;

struct proc_dir_entry* test_proc_entry;

#define BENCHMARK(bname)					\
	{										\
		.name = #bname , 					\
		.bench_init = bname ## _init,		\
		.bench_deinit = bname ## _deinit,	\
		.bench_func = bname ## _bench,		\
		.bench_get_results =				\
			bname ## _bench_results			\
	}

#define BENCHMARK2(bname)					\
	{										\
		.name = #bname , 					\
		.bench_func = bname ## _bench,		\
		.bench_get_results =				\
			bname ## _bench_results			\
	}

struct benchmark benchmarks[] =
{
	BENCHMARK(actor),
	BENCHMARK(multi_actor),
	BENCHMARK2(atomic),
	BENCHMARK2(percpu),
	BENCHMARK2(spinlock),
	BENCHMARK2(mutex),
	BENCHMARK(pp_actor),
	BENCHMARK(pp_thread),
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
	smp_mb();
}

int benchmark_thread(void* data) {
	struct benchmark* benchmark = NULL;
	bench_stage_t bs = BENCH_DONE;

	while((bs = benchmark_stage) != BENCH_DONE) {
		benchmark = benchmarks + bs;
		benchmark->bench_func(benchmark, data);
		smp_mb();
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

	for(i = 0; i < NUM_CLIENTS; ++i) {
		bench_threads[i] = kthread_create(benchmark_thread, NULL, "bench-%d", i);
		wake_up_process(bench_threads[i]);
	}

	return count;
}

int bench_init_benchmarks(void) {
	int i = BENCH_NONE + 1;

	for(; i < BENCH_DONE; ++i) {
		if(benchmarks[i].bench_init)
			benchmarks[i].bench_init();
	}

	return 0;
}

int bench_deinit_benchmarks(void) {
	int i = BENCH_NONE + 1;

	for(; i < BENCH_DONE; ++i) {
		if(benchmarks[i].bench_deinit)
			benchmarks[i].bench_deinit();
	}

	return 0;
}

int benchmark_init(void) {
	bench_init_benchmarks();

	if(IS_ERR(test_actor))
		return PTR_ERR(test_actor);


	bench_threads = kmalloc(sizeof(struct task_struct*) * num_clients, GFP_KERNEL);

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

	kfree(bench_threads);

	del_timer(&bench_timer);

	bench_deinit_benchmarks();
}

module_init(benchmark_init);
module_exit(benchmark_exit);
