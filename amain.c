#include <linux/types.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/module.h>
#include <asm/bitops.h>
#include <linux/time.h>

#include <actor.h>
#include <aproc.h>
#include <hwtopo.h>

/*Global cache for actor objects*/
static struct kmem_cache* actor_cache = NULL;
static struct kmem_cache* actor_work_cache = NULL;

/*Global actor UID*/
static volatile atomic_t actor_global_id;

/* Internal field that is set if actor thread is on CPU now
 * needed to checks of actor_communicate*/
static DEFINE_PER_CPU(actor_work_t*, actor_curwork);

static struct actor_head*	actor_list;

MODULE_LICENSE("GPL");

/*Forward declaration*/
int actor_kthread(void*);

#ifdef CONFIG_ACTOR_TRACE

#include <trace/events/actor.h>

DEFINE_TRACE(actor_event);

int __actor_trace(char* name, char* fmtstr, ...) {
	char buf[256];
	va_list args;
	int i = 0;

	va_start(args, fmtstr);
	i = vsnprintf(buf, INT_MAX, fmtstr, args);
	va_end(args);

	trace_actor_event(name, buf);

	return i;
}

#endif

static void actor_try_dispatch(actor_t* ac, actor_state_t new_state);
static void actor_node_init(int nodeid);
static void actor_node_timer_func(unsigned long data);

/*
* actor_init_cache inits actor kmem cache
* in case of fault returns -EFAULT
*/
int amod_init(void) {
	int i;

	cycles_t cyc = get_cycles();

	if(cyc == 0) {
		printk("Kernel should support get_cycles for actor internal scheduler");
		return -EFAULT;
	}

	actor_cache = kmem_cache_create("actor",
									sizeof(struct actor), 0, 0,
									NULL);
	actor_work_cache = kmem_cache_create("actor_work",
									sizeof(struct actor_work), 0, 0,
									NULL);
									
	if(!actor_cache  || !actor_work_cache)
		return -EFAULT;
	
	actor_list = kmalloc(sizeof(struct actor_head) * NR_CPUS, GFP_KERNEL);
	
	if(!actor_list) {
		kmem_cache_destroy(actor_cache);
		return -EFAULT;
	}
	
	aproc_init();

	/*Initialize actor heads*/
	HWTOPO_FOR_EACH_NODE(i) {
		actor_node_init(i);
    }
	
	return 0;
}

void amod_exit(void) {
	int i = 0;

	HWTOPO_FOR_EACH_NODE(i) {
		set_bit(ACTOR_NODE_STOP, &actor_list[i].ah_flags);

		del_timer(&actor_list[i].ah_timer);

		/*Complete what is left and exit*/
		kthread_stop(actor_list[i].ah_kthread);

		aproc_free_head(&actor_list[i]);
	}

	aproc_exit();

	kfree(actor_list);

	kmem_cache_destroy(actor_cache);
	kmem_cache_destroy(actor_work_cache);
}

module_init(amod_init);
module_exit(amod_exit);

/**
 * Creates new message: allocates memory using kmalloc and sets up structure
 * 
 * @param untyped_num number of untyped items
 * @param typed_num number of typed items
 * @param nodeid where message would be sent
 * 
 * For non-local messages allocation will be made using DMA zone (to reduce cache coherency)
 * and to node nodeid. Also, for non-local messages untyped items may be copied
 * 
 * TODO: untyped items locality
 */
amsg_hdr_t* amsg_create(u32 untyped_num, u32 typed_num, int nodeid) {
    u32 sz = sizeof(amsg_hdr_t) + untyped_num * sizeof(amsg_word_t) + 
                typed_num * sizeof(amsg_typed_t); 
                
    /* Allocate in uncached zone (DMA) to reduce number
     of cache misses when sender and receiver are located on
     different nodes*/
    amsg_hdr_t* msg = kmalloc(sz, GFP_KERNEL | (HWTOPO_NODE_ISLOCAL(nodeid))? 0 : GFP_DMA);    
    
    if(!msg)
        return NULL;
    
    msg->len = sz;
    msg->untyped = (amsg_word_t*) (char*) msg + sizeof(amsg_hdr_t);
    msg->typed = (amsg_typed_t*) ((char*) msg->untyped + untyped_num * sizeof(amsg_word_t));
    
    return msg;
}
EXPORT_SYMBOL_GPL(amsg_create);

void amsg_free(amsg_hdr_t* msg) {
	kfree(msg);
}
EXPORT_SYMBOL_GPL(amsg_free);

extern const char* aproc_actor_state_str(actor_state_t ac);

static A_NOINLINE void actor_set_state(actor_t* ac, actor_state_t newstate) {
	ADEBUG("actor_set_state", "Set state %s-%llu %s->%s\n", ac->a_name, ac->a_uid, 
					aproc_actor_state_str(ac->a_state), 
					aproc_actor_state_str(newstate));

	ac->a_state = newstate;
}

/**
 * Attach actor to desired node
 */
void actor_attach(actor_t* ac) {
	struct actor_head* ah = actor_list + ac->a_nodeid;

	spin_lock(&ah->ah_lock_init);
	list_add_tail(&ac->a_list, &ah->ah_queue_init);
	spin_unlock(&ah->ah_lock_init);

	actor_try_dispatch(ac, AS_NOT_INITIALIZED);

	set_bit(ACTOR_NODE_INIT, &ah->ah_flags);
}

/**
 * Creates new actor
 * 
 * @param flags flags, currently not used
 * @param prio priority (for scheduler)
 * @param nodeid node where actor is bound
 * @param name symbolic name of actor (not larger than ANAMEMAXLEN)
 *
 * @param ctor actor constructor
 * @param dtor actor destructor
 * @param f    actor's callback
 * @param data private data that passed as second argument to constructor
 * Prototype:  f(actor_t* self, amsg_hdr_t* msg)
 */
actor_t* actor_create(u32 flags, u32 prio, int nodeid, char* name,
		actor_ctor ctor, actor_dtor dtor, actor_callback f,
		void* data) {
	actor_t* ac = NULL;
	
	if(unlikely(!HWTOPO_NODE_CORRECT(nodeid))) 
		return ERR_PTR(-EFAULT);
	
	ac = kmem_cache_alloc(actor_cache, 0);
	
	if(unlikely(!ac))
		return ERR_PTR(-ENOMEM);
	
	/*Creating next UID*/
	ac->a_uid = atomic_inc_return((atomic_t*) &actor_global_id);
    ac->a_nodeid = nodeid;
    
	ac->a_flags = flags;
	ac->a_prio = prio;

	ac->a_exec.a_function = f;

	ac->a_ctor = ctor;
	ac->a_dtor = dtor;
    
    strncpy(ac->a_name, name, ANAMEMAXLEN);
    ac->a_name[ANAMEMAXLEN - 1] = 0;
	
    mutex_init(&ac->a_mutex);
    spin_lock_init(&ac->a_msg_lock);
    
    ac->a_private_temp = data;
    ac->a_private = NULL;
    ac->a_private_len = 0;

    INIT_LIST_HEAD(&(ac->a_work_message));
    INIT_LIST_HEAD(&(ac->a_work_active));

    actor_attach(ac);

    aproc_create_actor(ac);

	ADEBUG("actor_create", "Created new actor %s-%llu@%d [%p]\n", name, ac->a_uid, ac->a_nodeid, ac);
	
	return ac;
}
EXPORT_SYMBOL_GPL(actor_create);


/*
 * Allocate private data for actor. Needed for actor constructors
 * to allocate memory on node on which actor will work to ensure local access.
 *
 * When actor migrates to another node, data is reallocated on foreign node too.
 *
 * @param ac pointer to actor
 * @param len length of allocated area
 */
void* actor_private_allocate(actor_t* ac, unsigned long len) {
	/*Already allocated - fail*/
	if(ac->a_private_len != 0)
		return ERR_PTR(-EINVAL);

	ac->a_private = kmalloc(len, GFP_KERNEL);

	if(!ac->a_private)
		return ERR_PTR(-ENOMEM);

	ac->a_private_len = len;

	return ac->a_private;
}
EXPORT_SYMBOL_GPL(actor_private_allocate);

void actor_private_free(actor_t* ac) {
	if(ac->a_private)
		kfree(ac->a_private);
}
EXPORT_SYMBOL_GPL(actor_private_free);

/**
 * Destroy actor
 *
 * TODO: incomplete works
 * 
 * @param ac pointer to actor
 */
void actor_destroy(actor_t* ac) {
	aproc_free_actor(ac);

	spin_lock(&actor_list[ac->a_nodeid].ah_lock);
    list_del(&ac->a_list);
	spin_unlock(&actor_list[ac->a_nodeid].ah_lock);
    
    ADEBUG("actor_destroy", "Destroyed actor %s-%llu@%d [%p]\n", ac->a_name, ac->a_uid, ac->a_nodeid, ac);

    if(ac->a_dtor)
		ac->a_dtor(ac);

    kmem_cache_free(actor_cache, ac);
}
EXPORT_SYMBOL_GPL(actor_destroy);

/**
 * 
 * 
 * TODO: Add search via local hash table
 */

#if 0
actor_t* actor_byid(u64 id) {
    int nodeid = 0;
    struct list_head  *l = NULL,
                       *lh = NULL;
    actor_t* a = NULL;
    
    HWTOPO_FOR_EACH_NODE(nodeid) {
    	lh = &actor_list[nodeid].ah_list;

		list_for_each(l, lh) {
			a = container_of(l, actor_t, a_list);

			if(a->a_uid == id)
				return a;
		}
    }
    
    return NULL;
}
EXPORT_SYMBOL_GPL(actor_byid);
#endif

static A_NOINLINE actor_work_t* actor_work_create(actor_t* ac, amsg_hdr_t* msg) {
	actor_work_t* aw = kmem_cache_alloc(actor_work_cache, GFP_KERNEL);
	
	if(!aw)
		return NULL;
	
	aw->aw_actor = ac;
	aw->aw_msg = msg;
	
	aw->aw_wait_work = NULL;
	aw->aw_flags = 0;

	INIT_LIST_HEAD(&(aw->aw_list));
	
	init_completion(&(aw->aw_wait));

	return aw;
}

void actor_work_free(actor_work_t* aw) {
	amsg_free(aw->aw_msg);

	kmem_cache_free(actor_work_cache, aw);
}

/**
 * Try to dispatch actor on desired node
 */
static void actor_try_dispatch(actor_t* ac, actor_state_t new_state) {
	struct actor_head* ah = actor_list + ac->a_nodeid;

	actor_set_state(ac, new_state);

	/*Bit wasn't set, ensure that kthread will be dispatched*/
	if(!test_and_set_bit(ACTOR_NODE_DISPATCHED, &(ah->ah_flags)))
		wake_up_process(ah->ah_kthread);
}

actor_work_t* __actor_communicate(actor_t* ac, amsg_hdr_t* msg, int aw_flags) {
	actor_work_t* aw = NULL;
	
	if(!ac)
		return ERR_PTR(EFAULT);
	
	if(ac->a_state == AS_NOT_INITIALIZED)
		return ERR_PTR(EINVAL);

	aw = actor_work_create(ac, msg);
	aw->aw_flags = aw_flags;
	
	if(!aw)
		return ERR_PTR(EFAULT);
	
	/*Now put actor work on message queue*/
    spin_lock(&(ac->a_msg_lock));  
    list_add_tail(&(aw->aw_list), &(ac->a_work_message));
	spin_unlock(&(ac->a_msg_lock));
    
	/* FIXME: may sleep on inter-actor communication that is bad */
	mutex_lock(&ac->a_mutex);

	/* If actor was stopped - need redispatch him
	 * or it will be redispatched when actor_execute detects
	 * that queue is not empty*/
	if(ac->a_state == AS_STOPPED)
		actor_try_dispatch(ac, AS_RUNNABLE);

	mutex_unlock(&ac->a_mutex);

    return aw;
}

int actor_communicate(actor_t* ac, amsg_hdr_t* msg) {
	actor_work_t* aw = __actor_communicate(ac, msg, AW_NONE);

	if(likely(!IS_ERR(aw)))
		return 0;

	return PTR_ERR(aw);
}
EXPORT_SYMBOL_GPL(actor_communicate);

int actor_communicate_blocked(actor_t* ac, amsg_hdr_t* msg) {
	actor_work_t* aw = __actor_communicate(ac, msg, AW_BLOCKING);
	actor_work_t* curwork = NULL;

	if(likely(!IS_ERR(aw))) {
		curwork = get_cpu_var(actor_curwork);
		put_cpu_var(actor_curwork);

		if(!curwork) {
			/*THREAD -> ACTOR, threads may sleep*/
			wait_for_completion(&(aw->aw_wait));
		}
		else {
			/*ACTOR -> ACTOR*/
			aw->aw_wait_work = curwork;
			curwork->aw_flags |= AW_COMMUNICATING;
		}

		actor_work_free(aw);

		return 0;
	}

	return PTR_ERR(aw);
}
EXPORT_SYMBOL_GPL(actor_communicate_blocked);

/**
 * Attach message queue to the tail of active queue
 * 
 * @param ac actor
 */
A_NOINLINE void actor_queue_join(actor_t* ac)  {
    spin_lock(&ac->a_msg_lock);  
	
    list_splice_init(&ac->a_work_message, &ac->a_work_active);
    
    spin_unlock(&ac->a_msg_lock);
}

A_NOINLINE int actor_queue_isempty(actor_t* ac)  {
	int isempty = 0;

    spin_lock(&ac->a_msg_lock);
    isempty = list_empty(&ac->a_work_message) & list_empty(&ac->a_work_active);
    spin_unlock(&ac->a_msg_lock);

    return isempty;
}

/*
 * Execute work for actor
 *
 * TODO: pipelined actors
 * */
int actor_execute_work(actor_work_t* aw) {
	actor_t* ac = aw->aw_actor;

	ADEBUG("actor_execute", "Processing work %p for actor %s-%llu exec: %p\n", aw, ac->a_name, ac->a_uid,
	        		ac->a_exec.a_function);
	
	return ac->a_exec.a_function(ac, aw->aw_msg, aw->aw_flags) == 0;
}

void actor_finish_work(actor_work_t* aw) {
	actor_t* awaken = NULL;

	if(unlikely(!(aw->aw_flags & AW_BLOCKING))) {
		/* Unblocked communications are freed on receiver side*/
		actor_work_free(aw);
	}
	else {
		if(!aw->aw_wait_work) {
			complete(&(aw->aw_wait));
		}
		else {
			/*Release waiter*/
			awaken = aw->aw_wait_work->aw_actor;

			aw->aw_wait_work->aw_flags &= ~AW_COMMUNICATING;
			aw->aw_wait_work->aw_flags |= AW_COMM_COMPLETE;
			aw->aw_wait_work = NULL;

			/*Wake up after communication is complete*/
			actor_try_dispatch(awaken, AS_RUNNABLE);

			actor_work_free(aw);
		}
	}
}

int actor_select_queue(actor_t* ac, struct actor_head* ah, int actor_complete) {
    actor_state_t next_state = AS_STOPPED;
    struct list_head* next_queue = NULL;

	if(actor_complete == 0) {
		/*Not all works are completed successfully or timeslice exhausted*/
		next_state = AS_RUNNABLE_INCOMPLETE;
		next_queue = &ah->ah_queue_wait;
	}
	else {
		if(actor_queue_isempty(ac)) {
			next_state = AS_STOPPED;
		}
		else {
			next_state = AS_RUNNABLE;
			actor_complete = 0;
		}

		next_queue = &ah->ah_queue_stop;
	}

	spin_lock(&ah->ah_lock);
	actor_set_state(ac, next_state);
	list_add_tail(&ac->a_list, next_queue);
	spin_unlock(&ah->ah_lock);

	return actor_complete;
}

/**
 * Process actor messages 
 *
 * TODO: must contain message arbiter
 * 
 * @param ac actor to execute
 */
int actor_execute(actor_t* ac, struct actor_head* ah, struct timespec ts_end) {
    struct list_head *l = NULL, *ln = NULL;
    actor_work_t* aw = NULL;
    int actor_complete = 0, work_complete = 0;

    struct timespec ts_now;

    actor_queue_join(ac);

    /* Messaging queue was empty too, discard actor */
    if(list_empty(&ac->a_work_active)) {
    	actor_complete = 1;
    	goto out;
    }

	ac->a_jiffies = jiffies;
	actor_set_state(ac, AS_EXECUTING);

	/*No need to hold a_mutex while we are processing works*/
	mutex_unlock(&ac->a_mutex);

	while(!actor_complete) {
		actor_complete = 1;

		list_for_each_safe(l, ln, &ac->a_work_active) {
			aw = (actor_work_t*) list_entry(l, actor_work_t, aw_list);

			if(aw->aw_flags & AW_COMMUNICATING) {
				/* Actor is not marked as incomplete. When work is completed,
				 * actor_finish_work will call actor_try_dispatch*/
				continue;
			}

			/* Set current work pointer*/
			get_cpu_var(actor_curwork) = aw;
			put_cpu_var(actor_curwork);

			work_complete = actor_execute_work(aw);
			actor_complete &= work_complete;

			if(work_complete) {
				list_del(l);

				actor_finish_work(aw);
			}

			getnstimeofday(&ts_now);
			if(timespec_compare(&ts_now, &ts_end) >= 0) {
				actor_complete = 0;
				goto finish;
			}
		}
	}

finish:
	get_cpu_var(actor_curwork) = NULL;
	put_cpu_var(actor_curwork);

    ADEBUG("actor_execute_done", "Executed actor %s-%llu\n", ac->a_name, ac->a_uid);

	mutex_lock(&ac->a_mutex);

out:
	/*Finished execution*/

	return actor_complete;
}

static void actor_node_init(int nodeid) {
	struct actor_head* ah = actor_list + nodeid;

	spin_lock_init(&ah->ah_lock);
    spin_lock_init(&ah->ah_lock_init);

    ah->ah_nodeid = nodeid;

	INIT_LIST_HEAD(&(ah->ah_queue_exec));
	INIT_LIST_HEAD(&(ah->ah_queue_init));
	INIT_LIST_HEAD(&(ah->ah_queue_migr));
	INIT_LIST_HEAD(&(ah->ah_queue_stop));
	INIT_LIST_HEAD(&(ah->ah_queue_wait));

	ah->ah_num_actors = 0;

	ah->ah_flags = 0;

	ah->ah_kthread = kthread_create(actor_kthread, ah, "kactor-%d", nodeid);
	kthread_bind(ah->ah_kthread, nodeid);

	init_completion(&ah->ah_wait);

	init_timer(&ah->ah_timer);
	setup_timer(&ah->ah_timer, actor_node_timer_func, (unsigned long) ah);

	aproc_create_head(ah);
}

/*
 * Initialize actors that are not initialized yet
 * */
void actor_node_init_actors(struct actor_head* ah) {
	actor_t* a = NULL;
	struct list_head  *l = NULL, *ln = NULL,
					  *lh_init = &ah->ah_queue_init;

	spin_lock(&(ah->ah_lock_init));
	spin_lock(&(ah->ah_lock));
	list_for_each_safe(l, ln, lh_init) {
		a = list_entry(l, actor_t, a_list);

		if(a->a_ctor)
			a->a_ctor(a, a->a_private_temp);

		list_del(l);

		++ah->ah_num_actors;

		actor_set_state(a, AS_STOPPED);
		list_add_tail(l, &ah->ah_queue_stop);
	}
	spin_unlock(&(ah->ah_lock));
	spin_unlock(&(ah->ah_lock_init));
}

/**
 * Actor softirq main routine.
 *
 * TODO: scheduler/dispatcher
 */

/*Attach node queue to exec*/
#define ATTACH_NODE_QUEUE(ah, queue) 			\
		spin_lock(&ah->ah_lock);				\
		list_splice_init(&ah->queue, 			\
					&ah->ah_queue_exec);		\
		spin_unlock(&ah->ah_lock);

int __actor_node_process(struct actor_head* ah, struct timespec ts_end) {
    struct list_head  *l = NULL, *ln = NULL,
                       *lh = NULL;

    actor_t* a = NULL;
    int node_processed = 1, actor_complete = 0;

    struct timespec ts_actor_end, ts_now, ts_actor_slice;

    /* No actors are attached to this node.
     * Strange but OK*/
    if(ah->ah_num_actors == 0)
    	return 1;

    getnstimeofday(&ts_now);
    ts_actor_slice = timespec_sub(ts_end, ts_now);
    ts_actor_slice.tv_nsec /= ah->ah_num_actors;

	ATTACH_NODE_QUEUE(ah, ah_queue_stop);

	lh = &ah->ah_queue_exec;

	/*Execute actors for CURRENT node*/
	list_for_each_safe(l, ln, lh) {
		a = list_entry(l, actor_t, a_list);
		list_del(l);

		getnstimeofday(&ts_now);
		ts_actor_end = timespec_add(ts_now, ts_actor_slice);

		/*
		 * 0 - actor was executed but didn't completed
		 * 1 - actor was completed or wasn't executed
		 * */
		actor_complete = 1;

		mutex_lock(&(a->a_mutex));

		/*If actor is runnable (e.g. communication has started)
		 or it was not processed successfully during last timeslice*/
		if(a->a_state == AS_RUNNABLE ||
		   a->a_state == AS_RUNNABLE_INCOMPLETE)
			actor_complete = actor_execute(a, ah, ts_actor_end);

		actor_complete = actor_select_queue(a, ah, actor_complete);
		mutex_unlock(&(a->a_mutex));

		/* Timeslice exhausted */
		getnstimeofday(&ts_now);
		if(timespec_compare(&ts_now, &ts_end) >= 0) {
			break;
		}
	}
	
	/*Check queues*/
	spin_lock(&ah->ah_lock);
	node_processed = list_empty(&ah->ah_queue_exec) && list_empty(&ah->ah_queue_wait);
	spin_unlock(&ah->ah_lock);

	return node_processed;
}


int actor_node_process(struct actor_head* ah) {
	int node_processed = 0;

	/*Scheduler timing structures*/
	struct timespec ts_end, ts_now;
	u64 time_slice = NSEC_PER_USEC * jiffies_to_usecs(1);

	struct timespec ts_slice = { .tv_sec = 0,
			.tv_nsec = time_slice };

	getnstimeofday(&ts_now);
	ts_end = timespec_add(ts_now, ts_slice);

    ADEBUG("actor_node_process", "Actor node process @%d\n", ah->ah_nodeid);

    if(test_and_clear_bit(ACTOR_NODE_INIT, &ah->ah_flags))
    	actor_node_init_actors(ah);

    /*Attach all waiters*/
    ATTACH_NODE_QUEUE(ah, ah_queue_wait);

    node_processed = __actor_node_process(ah, ts_end);

    if(!node_processed) {
    	set_bit(ACTOR_NODE_DISPATCHED, &ah->ah_flags);

    	/*Allow other processes to run but we are not done yet*/
    	yield();
    }

    return node_processed;
}

/** 
 * Actor's kthread
 */
int actor_kthread_exec(struct actor_head* ah) {
	/*Sleep until somebody will dispatch us*/
	while(!test_and_clear_bit(ACTOR_NODE_DISPATCHED, &(ah->ah_flags)) &&
			!test_bit(ACTOR_NODE_STOP, &(ah->ah_flags))) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
		set_current_state(TASK_RUNNING);
	}

	actor_node_process(ah);

	return 0;
}

int actor_kthread(void* data) {
	struct actor_head* ah = (struct actor_head*) data;
	
	while (!kthread_should_stop()) {
		actor_kthread_exec(ah);
	}

	return 0;
}


static void actor_node_timer_func(unsigned long data) {
	struct actor_head* ah = (struct actor_head*) data;

	wake_up_process(ah->ah_kthread);
}
