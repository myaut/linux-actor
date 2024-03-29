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

#ifdef CONFIG_ACTOR_LOCK_TIMING
DECLARE_ALOCK_TIMING(alock_message);
DECLARE_ALOCK_TIMING(alock_work);
DECLARE_ALOCK_TIMING(alock_amutex);
DECLARE_ALOCK_TIMING(alock_node);

#define AMUTEX_LOCK(ac)	    if(!mutex_trylock(&ac->a_mutex)) {		\
									++alock_amutex.busy;			\
									mutex_lock(&ac->a_mutex);		\
							}										\
							++alock_amutex.count

#define AMUTEX_SPIN(ac)	    if(!mutex_trylock(&ac->a_mutex)) {			\
									++alock_amutex.busy;				\
									while(!mutex_trylock(&ac->a_mutex))	\
											cpu_relax();				\
							}											\
							++alock_amutex.count

#define TIMED_SPINLOCK(sl, sltm)							\
							if(!spin_trylock(&sl)) {		\
									++sltm.busy;			\
									spin_lock(&sl);			\
							}								\
							++sltm.count

#define AMESSAGE_LOCK(am)	TIMED_SPINLOCK(am.lock, alock_message)
#define ANODE_LOCK(ah)		TIMED_SPINLOCK(ah->ah_lock, alock_node)
#define AWORK_LOCK(aw)		TIMED_SPINLOCK(aw->aw_lock, alock_work)

#else

#define AMUTEX_LOCK(ac)		mutex_lock(&ac->a_mutex)
#define AMESSAGE_LOCK(am)	spin_lock(&am.lock)
#define ANODE_LOCK(ah)		spin_lock(&ah->ah_lock)
#define AWORK_LOCK(aw)		spin_lock(&aw->aw_lock)
#define AMUTEX_SPIN(ac)		while(!mutex_trylock(&ac->a_mutex))	\
								cpu_relax();

#endif

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

static actor_work_t* get_current_work(void) {
    /* Curwork should be NULL if kactor-thread not on CPU */
    ACTOR_CHECK( percpu_read_stable(actor_curwork) != NULL &&
            	 current != actor_list[smp_processor_id()].ah_kthread);
    
    return percpu_read_stable(actor_curwork);
}
	
/*
* actor_init_cache inits actor kmem cache
* in case of fault returns -EFAULT
*/
int amod_init(void) {
	int i;
    
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
 * @param ae desired pipeline. If NULL - uses default actor's pipeline
 * @param nodeid nodeid, where message would be sent (needed for better localiness)
 * 
 * For non-local messages allocation will be made using DMA zone (to reduce cache coherency)
 * and to node nodeid. Also, for non-local messages untyped items may be copied
 * 
 * TODO: untyped items locality
 */
amsg_hdr_t* amsg_create(u32 untyped_num, u32 typed_num, actor_exec_t* ae, int nodeid) {
    u32 sz = sizeof(amsg_hdr_t) + untyped_num * sizeof(amsg_word_t) + 
                typed_num * sizeof(amsg_typed_t); 
                
    /* Allocate in uncached zone (DMA) to reduce number
     of cache misses when sender and receiver are located on
     different nodes.*/
    amsg_hdr_t* msg = kmalloc(sz, GFP_ATOMIC | (HWTOPO_NODE_ISLOCAL(nodeid))? 0 : GFP_DMA);
    
    if(!msg)
        return NULL;
    
    atomic_set(&msg->am_count, 0);

    msg->am_exec = ae;

    msg->am_untyped_num = untyped_num;
    msg->am_typed_num = typed_num;
    
    return msg;
}
EXPORT_SYMBOL_GPL(amsg_create);

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

	set_bit(ACTOR_NODE_INIT, &ah->ah_flags);
	
	mutex_lock(&ac->a_mutex);
	actor_try_dispatch(ac, AS_NOT_INITIALIZED);
	mutex_unlock(&ac->a_mutex);
}

/**
 * Detach actor from it's node
 */
void actor_detach(actor_t* ac) {
    spinlock_t* node_lock;
    
    mutex_lock(&ac->a_mutex);
    
    switch(ac->a_state) {
        case AS_NOT_INITIALIZED:
            node_lock = &actor_list[ac->a_nodeid].ah_lock;
        break;
        default:
            node_lock = &actor_list[ac->a_nodeid].ah_lock_init;
    }
    
    /*Delete actor from queue*/
    spin_lock(node_lock);
    list_del(&ac->a_list);
    spin_unlock(node_lock);
    
    mutex_unlock(&ac->a_mutex);
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
		actor_ctor ctor, actor_dtor dtor, actor_exec_t* ae,
		void* data) {
	actor_t* ac = NULL;
	int i;
	
	if(unlikely(!HWTOPO_NODE_CORRECT(nodeid) || !ae ))
		return ERR_PTR(-EFAULT);
	
	ac = kmem_cache_alloc(actor_cache, GFP_KERNEL);
	
	if(unlikely(!ac))
		return ERR_PTR(-ENOMEM);
	
	/*Creating next UID*/
	ac->a_uid = atomic_inc_return((atomic_t*) &actor_global_id);
    ac->a_nodeid = nodeid;
    
	ac->a_flags = flags;
	ac->a_prio = prio;

	ac->a_exec = ae;

	ac->a_ctor = ctor;
	ac->a_dtor = dtor;
    
#   ifdef CONFIG_ACTOR_DEBUG
    ac->a_magic = ACTOR_MAGIC;
#   endif
    
    strncpy(ac->a_name, name, ANAMEMAXLEN);
    ac->a_name[ANAMEMAXLEN - 1] = 0;
	
    mutex_init(&ac->a_mutex);
    
    ac->a_private_temp = data;
    ac->a_private = NULL;
    ac->a_private_len = 0;

    ac->a_jiffies = 0;

    ac->a_max_qlen = CONFIG_ACTOR_MAX_QLEN;
    atomic_set(&ac->a_qlen, 0);
    init_waitqueue_head(&ac->a_queue_wq);

    HWTOPO_FOR_EACH_NODE(i) {
    	spin_lock_init(&AWORK_MESSAGE(ac, i).lock);
    	INIT_LIST_HEAD(&AWORK_MESSAGE(ac, i).queue);
    }

    INIT_LIST_HEAD(&(ac->a_work_active));

    init_completion(&(ac->a_destroy_wait));
    
    aproc_create_actor(ac);

	ADEBUG("actor_create", "Created new actor %s-%llu@%d [%p]\n", name, ac->a_uid, ac->a_nodeid, ac);
	
	actor_attach(ac);
	
	return ac;
}
EXPORT_SYMBOL_GPL(actor_create);


/**
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

	ac->a_private = kmalloc(len, GFP_ATOMIC);

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
 * Destroy actor. Set's actor state to AS_FROZEN, so it 
 * prevents other to send messages to actor.
 * 
 * Sleeps until actor completes all its works (may sleep eternally!)
 * 
 * Calls actor's destructor if needed
 * 
 * @param ac pointer to actor
 */
void actor_destroy(actor_t* ac) {
    actor_state_t prev_state;
    
	aproc_free_actor(ac);

    AMUTEX_LOCK(ac);
    
    prev_state = ac->a_state;
    ac->a_state = AS_FROZEN;
    
    mutex_unlock(&ac->a_mutex);
    
    /*Wait until actor finish it's messages, also 
     actor_node_process detaches actor from queue*/
    if(ACTOR_IS_RUNNABLE(prev_state))
        wait_for_completion(&ac->a_destroy_wait);
    
    ADEBUG("actor_destroy", "Destroyed actor %s-%llu@%d [%p]\n", ac->a_name, ac->a_uid, ac->a_nodeid, ac);

    if(ac->a_dtor)
		ac->a_dtor(ac);

    kmem_cache_free(actor_cache, ac);
}
EXPORT_SYMBOL_GPL(actor_destroy);

/**
 * Allocate and initialize new work for actor ac
 * 
 * Increases reference counter for msg
 * 
 * @param ac actor
 * @param msg message
 * @param flags initial value of flags (i.e. AW_NONE, AW_BLOCKING)
 * 
 * @return pointer to allocated actor work or NULL in case of error \ 
 * (incorrect state of actor, allocation failure)
 * */
static actor_work_t* actor_work_create(actor_t* ac, amsg_hdr_t* msg, u64 flags) {
	actor_work_t* aw = NULL;
    
	ACTOR_MAGIC_CHECK(ac);

#ifdef CONFIG_ACTOR_DEBUG
    if(WARN(!ac, "actor_work_create: ac == (null)\n") ||
       WARN(!msg, "actor_work_create: msg == (null) actor is %p", ac))
    	return NULL;
#endif
	
    if(ac->a_state == AS_FROZEN)
        return NULL;

    flags |= (get_current_work() == NULL) ? 0 : AW_ATOMIC;

	aw = kmem_cache_alloc(actor_work_cache, (flags & AW_ATOMIC)
												? GFP_ATOMIC
												: GFP_KERNEL);
	
	if(!aw)
		return NULL;
	
	aw->aw_actor = ac;

	atomic_inc(&msg->am_count);
	aw->aw_msg = msg;
	
	aw->aw_wait_work = NULL;
	aw->aw_flags = flags;

	atomic_set(&aw->aw_count, 1);

	spin_lock_init(&aw->aw_lock);
	INIT_LIST_HEAD(&aw->aw_list);

#ifdef CONFIG_ACTOR_DEBUG
	atomic_set(&aw->aw_hist_index, 0);
#endif

	return aw;
}

/**
 * Increase work's reference count
 */
void actor_work_hold(actor_work_t* aw) {
	atomic_inc(&aw->aw_count);
	smp_mb();
    
	AWORK_HIST_ADD(aw, 'H');
}

/**
 * Decrease work's ref count and message ref count
 * If needed, frees work and message
 * 
 * @return 1 if work was freed, 0 if not
 */
int actor_work_rele(actor_work_t* aw) {
    int rc;

	AWORK_HIST_ADD(aw, 'R');
	
	rc = atomic_dec_and_test(&aw->aw_count);
    smp_mb();
    
    if(rc) {  
		if(atomic_dec_and_test(&aw->aw_msg->am_count))
			kfree(aw->aw_msg);

		kmem_cache_free(actor_work_cache, aw);

		return 1;
	}

	return 0;
}

/**
 * Try to dispatch actor on desired node
 */
static void actor_try_dispatch(actor_t* ac, actor_state_t new_state) {
	struct actor_head* ah = actor_list + ac->a_nodeid;

	ADEBUG("actor_try_dispatch", "Trying to dispatch actor %s-%llu@%d [%p] with state=%s",
			 	 ac->a_name, ac->a_uid, ac->a_nodeid, ac, aproc_actor_state_str(new_state));

	ACTOR_MAGIC_CHECK(ac);
	ACTOR_CHECK(!mutex_is_locked(&ac->a_mutex));

	actor_set_state(ac, new_state);
	
	/*Attach to waiters queue if needed*/
	if(ACTOR_IS_RUNNABLE(new_state)) {
		list_del(&ac->a_list);

		ANODE_LOCK(ah);
		list_add_tail(&ac->a_list, &ah->ah_queue_wait);
		spin_unlock(&ah->ah_lock);
	}

	/*Bit wasn't set, ensure that kthread will be dispatched*/
	if(!test_and_set_bit(ACTOR_NODE_DISPATCHED, &(ah->ah_flags)))
		wake_up_process(ah->ah_kthread);
}

/**
 * Put work on actor's message queue
 * 
 * If needed, dispatches actor on it's node
 */
void actor_put_work(actor_t* ac, actor_work_t* aw) {
	ADEBUG("actor_put_work", "Put work %s[%d] -> %s-%llu@%d [%p] work: %p\n",
		    current->comm, current->pid, ac->a_name, ac->a_uid, ac->a_nodeid, ac, aw );

	ACTOR_MAGIC_CHECK(ac);
	ACTOR_CHECK(aw->aw_actor != ac);
	
	AWORK_HIST_ADD(aw, 'P');
	
	/*Now put actor work on message queue*/
    AMESSAGE_LOCK(AWORK_MESSAGE_THIS(ac));
    list_add_tail(&(aw->aw_list), &(AWORK_MESSAGE_THIS(ac).queue));
	smp_mb();

	spin_unlock(&(AWORK_MESSAGE_THIS(ac).lock));

	/* If actor was stopped - need redispatch him
	 * or it will be redispatched when actor_execute detects that queue is not empty*/
	if(ac->a_state == AS_STOPPED) {
		AMUTEX_SPIN(ac);

		if(ac->a_state == AS_STOPPED)
			actor_try_dispatch(ac, AS_RUNNABLE);

		mutex_unlock(&ac->a_mutex);
	}
}

static long actor_free_slots(actor_t* ac) {
	return ac->a_max_qlen - atomic_read(&ac->a_qlen);
}

/**
 * Communicate with actor. 
 * 
 * @note This function doesn't checks anything, so it can flood actor with \
 * messages. Use only in cases when you cannot sleep (i.e. interrupt).
 * 
 * @see actor_communicate_blocked
 * @see actor_communicate_async
 */
int actor_communicate(actor_t* ac, amsg_hdr_t* msg) {
	actor_work_t* aw = actor_work_create(ac, msg, AW_NONE);

	if(unlikely(!aw))
		return -EFAULT;

	actor_put_work(ac, aw);

	return 0;
}
EXPORT_SYMBOL_GPL(actor_communicate);

/**
 * Asynchronous communication with actor.
 *
 * Sleeps if there are too little slots on queue. When slot is freed (i.e. execution of
 * actor), task wakes up on wait_queue
 * Cannot be called from actor context, use actor_communicate in that case.
 * */
int actor_communicate_async(actor_t* ac, amsg_hdr_t* msg) {
	actor_work_t* aw = NULL;
	int rc = 0;

	ACTOR_CHECK(get_current_work() != NULL);

	if(unlikely(actor_free_slots(ac) < ACTOR_QLEN_THRESHOLD)) {
		rc = wait_event_interruptible(ac->a_queue_wq,
						actor_free_slots(ac) >= ACTOR_QLEN_THRESHOLD);

		if(rc != 0)
			return rc;
	}

	atomic_inc(&ac->a_qlen);

	aw = actor_work_create(ac, msg, AW_ASYNCHRONOUS);

	if(unlikely(!aw))
		return -EFAULT;

	actor_put_work(ac, aw);

	return 0;
}
EXPORT_SYMBOL_GPL(actor_communicate_async);

/**
 * Blocked communication with actor
 * 
 * When called from actor context, it hold's execution of
 * work until ac processes message than work is redispatched
 * (and issue callback again)
 * 
 * When called from thread context, it uses completion mechanism
 */
int actor_communicate_blocked(actor_t* ac, amsg_hdr_t* msg) {
	actor_work_t* aw = actor_work_create(ac, msg, AW_BLOCKING);
    actor_work_t* curwork = get_current_work();
    
	if(likely(aw)) {
		if(!curwork) {
			/*THREAD -> ACTOR, threads may sleep*/
			init_completion(&aw->aw_wait);

			AWORK_HIST_ADD(aw, 'T');
                        
			actor_work_hold(aw);
			actor_put_work(ac, aw);
			
			while(wait_for_completion_timeout(&(aw->aw_wait), HZ) == 0) {
				pr_warn("Execution of work %p took more than a second", aw);
				BUG();
			}

			actor_work_rele(aw);
		}
		else {
			/*ACTOR -> ACTOR*/
			AWORK_LOCK(curwork);
			if(curwork->aw_flags & AW_COMMUNICATING) {
#ifdef CONFIG_ACTOR_DEBUG
				pr_warn("New communications cannot be started, actor %s-%llu",
								curwork->aw_actor->a_name,
								curwork->aw_actor->a_uid);
#endif
				spin_unlock(&curwork->aw_lock);
				return -EINVAL;
			}

			if(curwork->aw_comm_count == AMAXCOMM) {
#ifdef CONFIG_ACTOR_DEBUG
				pr_warn("Too many communications are made by actor %s-%llu",
								curwork->aw_actor->a_name,
								curwork->aw_actor->a_uid);
#endif
				spin_unlock(&curwork->aw_lock);
				return -EINVAL;
			}

			curwork->aw_flags |= AW_COMMUNICATING;

			AWORK_HIST_ADD(aw, 'A');
            AWORK_HIST_ADD(curwork, '>');

			actor_work_hold(curwork);
			aw->aw_wait_work = curwork;

#ifdef CONFIG_ACTOR_DEBUG
			curwork->aw_last_comm = aw;
#endif
			aw->aw_ww_comm = curwork->aw_comm_count++;

			spin_unlock(&curwork->aw_lock);

			actor_put_work(ac, aw);
		}

		return 0;
	}

	return -EFAULT;
}
EXPORT_SYMBOL_GPL(actor_communicate_blocked);

/**
 * Attach message queue to the tail of active queue
 * 
 * @param ac actor
 */
A_NOINLINE void actor_queue_join(actor_t* ac)  {
	int i = 0;

	HWTOPO_FOR_EACH_NODE(i) {
		AMESSAGE_LOCK(AWORK_MESSAGE(ac, i));
		list_splice_tail_init(&(AWORK_MESSAGE(ac, i).queue), &ac->a_work_active);
		smp_mb();	/*work_message reinitiated, say this to other nodes*/
		spin_unlock(&(AWORK_MESSAGE(ac, i).lock));
	}
}

/**
 * Check if there are messages on queue
 *
 * @param ac actor 
 */
A_NOINLINE int actor_queue_isempty(actor_t* ac)  {
	int isempty = 1;
	int i = 0;

	if(!list_empty(&ac->a_work_active))
		return 0;

	HWTOPO_FOR_EACH_NODE(i) {
		AMESSAGE_LOCK(AWORK_MESSAGE(ac, i));
		if(isempty)
			isempty &= list_empty(&(AWORK_MESSAGE(ac, i).queue));
		spin_unlock(&(AWORK_MESSAGE(ac, i).lock));
	}

    return isempty;
}

/**
 * Execute work for actor
 * */
int actor_execute_work(actor_t* ac, actor_work_t* aw) {
	int rc;
	actor_exec_t* ae = aw->aw_msg->am_exec;
	actor_callback callback;
	
	ACTOR_MAGIC_CHECK(ac);
	AWORK_HIST_ADD(aw, '1');
	
	/*Fail back to default pipeline*/
	if(unlikely(!ae))
		ae = ac->a_exec;

	callback = ae->ae_pipeline[aw->aw_pipe_count];

	if(unlikely(!callback)) {
		pr_warn("Reached end of actor pipeline for %s-%llu", ac->a_name, ac->a_uid);
		BUG();
	}

	ADEBUG("actor_execute", "Processing work %p for actor %s-%llu exec: %p\n", aw, ac->a_name, ac->a_uid,
	        		ac->a_exec);
    
    preempt_disable();
    percpu_write(actor_curwork, aw);

	rc = callback(ac, aw);

    percpu_write(actor_curwork, NULL);
	preempt_enable();
    
	AWORK_HIST_ADD(aw, '2');
	
	return rc;
}

/**
 * Finish work for actor
 * 
 * In case of inter-actor communication, releases waiter 
 */
void actor_finish_work(actor_work_t* aw) {
	actor_t* awaken = NULL;
	actor_work_t* wait_work = NULL;
	int redispatch = 0;

	AWORK_HIST_ADD(aw, 'F');
	
	if(likely(aw->aw_flags & AW_BLOCKING)) {
		if(!aw->aw_wait_work) {
			complete(&aw->aw_wait);
		}
		else {
			/*Release waiter*/
			wait_work = aw->aw_wait_work;
			awaken = wait_work->aw_actor;
			
			ACTOR_MAGIC_CHECK(awaken);
			
			AWORK_LOCK(wait_work);

			wait_work->aw_flags |= AW_COMM_COMPLETE;
			wait_work->aw_comm_flags |= 1 << aw->aw_ww_comm;

			if(--wait_work->aw_comm_count == 0)
				wait_work->aw_flags &= ~AW_COMMUNICATING;

			if(!(wait_work->aw_flags & (AW_EXECUTING | AW_REDISPATCHED | AW_FINISHED))) {
				redispatch = 1;
				wait_work->aw_flags |= AW_REDISPATCHED;
			}

			spin_unlock(&wait_work->aw_lock);

			ADEBUG("actor_finish_work", "Releasing waiter %s-%llu %p\n", awaken->a_name,
						awaken->a_uid, awaken);

#ifdef CONFIG_ACTOR_DEBUG
			if(wait_work->aw_last_comm == aw)
				wait_work->aw_last_comm = NULL;
#endif

			actor_work_rele(wait_work);

			if(redispatch)
				actor_put_work(awaken, wait_work);
		}
	}

	actor_work_rele(aw);
}

/**
 * Desides, where to dispatch actor
 * 
 * @param ac actor
 * @param ah actor's head for node
 * @param actor_complete set to 1 if all of processed works returned ACTOR_COMPLETE
 */
int actor_select_queue(actor_t* ac, struct actor_head* ah, int actor_complete) {
    actor_state_t next_state = AS_STOPPED;
    struct list_head* next_queue = NULL;

    /* When actor_queue_isempty is concurrently called with actor_put_work,
     * it may return false even if put work already added message to queue
     * (because there are one queue per cpu)
     *
     * So we say actor_put_work that it should try to redispatch actor even if actor_select_queue
     * already called
     * */
    actor_set_state(ac, AS_STOPPED);
    smp_mb();

	if(actor_complete == 0) {
		/*Not all works are completed successfully or timeslice exhausted*/
		next_state = AS_RUNNABLE_INCOMPLETE;
		next_queue = &ah->ah_queue_wait;
	}
	else {
		if(actor_queue_isempty(ac)) {
			next_state = AS_STOPPED;
			next_queue = &ah->ah_queue_stop;
		}
		else {
			/*Received new messages while executing*/
			next_state = AS_RUNNABLE;
			actor_complete = 0;
			next_queue = &ah->ah_queue_wait;
		}
	}

	ACTOR_CHECK(!mutex_is_locked(&ac->a_mutex));

	ANODE_LOCK(ah);
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
int actor_execute(actor_t* ac, struct actor_head* ah) {
    struct list_head *l = NULL, *ln = NULL;
    actor_work_t* aw = NULL;
    int actor_complete = 1, work_status = 0, finish_work = 0;

    LIST_HEAD(a_work_incomplete);

    actor_queue_join(ac);

    /* Messaging queue was empty too, discard actor */
    if(list_empty(&ac->a_work_active)) {
    	goto out;
    }

	ac->a_jiffies = jiffies;
	actor_set_state(ac, AS_EXECUTING);

	/*No need to hold a_mutex while we are processing works*/
	mutex_unlock(&ac->a_mutex);

	list_for_each_safe(l, ln, &ac->a_work_active) {
		aw = (actor_work_t*) list_entry(l, actor_work_t, aw_list);

		ACTOR_MAGIC_CHECK(aw->aw_actor);

		AWORK_LOCK(aw);
		aw->aw_flags |= AW_EXECUTING;
		aw->aw_flags &= ~AW_REDISPATCHED;
		spin_unlock(&aw->aw_lock);

		list_del(l);
		
		finish_work = 0;
		work_status = actor_execute_work(ac, aw);

		AWORK_LOCK(aw);
		if(work_status != ACTOR_INCOMPLETE_STAGE)
			++aw->aw_pipe_count;

		/*Not started communication or all comms are complete*/
		if(!(aw->aw_flags & AW_COMMUNICATING)) {
			if(work_status != ACTOR_SUCCESS) {
				AWORK_HIST_ADD(aw, 'I');
				list_add(l, &a_work_incomplete);
				actor_complete = 0;

				aw->aw_flags |= AW_REDISPATCHED;
			}
			else {
				if(aw->aw_flags & AW_ASYNCHRONOUS) {
					/* If async queue was full, wakeup threads concurrently*/
					if(atomic_dec_return(&ac->a_qlen) <= ACTOR_WAKEUP_THRESHOLD)
						wake_up_all(&ac->a_queue_wq);
				}

				finish_work = 1;
				aw->aw_flags |= AW_FINISHED;
			}
		}

		aw->aw_flags &= ~AW_EXECUTING;
		spin_unlock(&aw->aw_lock);

		if(finish_work)
			actor_finish_work(aw);
	}
	
	list_splice(&a_work_incomplete, &ac->a_work_active);

    ADEBUG("actor_execute_done", "Executed actor %s-%llu\n", ac->a_name, ac->a_uid);

	AMUTEX_LOCK(ac);

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

/**
 * Initialize actors that are not initialized yet
 * */
void actor_node_init_actors(struct actor_head* ah) {
	actor_t* a = NULL;
	struct list_head  *l = NULL, *ln = NULL,
					  *lh_init = &ah->ah_queue_init;

	spin_lock(&(ah->ah_lock_init));
	list_for_each_safe(l, ln, lh_init) {
		a = list_entry(l, actor_t, a_list);

		if(a->a_ctor)
			a->a_ctor(a, a->a_private_temp);

		list_del(l);

		++ah->ah_num_actors;

		/*New messages may arrive while we are initializing actor*/
		while(!mutex_trylock(&a->a_mutex))
            cpu_relax();
        
		actor_select_queue(a, ah, 1);
		mutex_unlock(&a->a_mutex);
	}
	spin_unlock(&(ah->ah_lock_init));
}

/**
 * Actor softirq main routine.
 *
 * TODO: scheduler/dispatcher
 */

/*Attach node queue to exec*/
#define ATTACH_NODE_QUEUE(ah, queue) 			\
		ANODE_LOCK(ah);							\
		list_splice_init(&ah->queue, 			\
					&ah->ah_queue_exec);		\
		spin_unlock(&ah->ah_lock);

int __actor_node_process(struct actor_head* ah) {
    struct list_head  *l = NULL, *ln = NULL;

    actor_t* a = NULL;
    int node_processed = 1, actor_complete = 0;

    /* No actors are attached to this node.
     * Strange but OK*/
    if(ah->ah_num_actors == 0)
    	return 1;

	/*Execute actors for CURRENT node*/
	list_for_each_safe(l, ln, &ah->ah_queue_exec) {
		a = list_entry(l, actor_t, a_list);
        ACTOR_MAGIC_CHECK(a);
        
		/*
		 * 0 - actor was executed but didn't completed
		 * 1 - actor was completed or wasn't executed
		 * */
		actor_complete = 1;
        
		AMUTEX_LOCK(a);
		list_del_init(l);

		/*If actor is runnable (e.g. communication has started)
		 or it was not processed successfully during last timeslice*/
		if(ACTOR_IS_RUNNABLE(a->a_state))
			actor_complete = actor_execute(a, ah);
           
        if(unlikely(a->a_state == AS_FROZEN && actor_complete)) {
            complete(&a->a_destroy_wait);
        }
        else {
            actor_complete = actor_select_queue(a, ah, actor_complete);
        }

		mutex_unlock(&(a->a_mutex));
	}
	
	/*Check queues*/
	ANODE_LOCK(ah);
	node_processed = list_empty(&ah->ah_queue_exec) && list_empty(&ah->ah_queue_wait);
	spin_unlock(&ah->ah_lock);

	return node_processed;
}


int actor_node_process(struct actor_head* ah) {
	int node_processed = 0;

	while(!node_processed) {
		ADEBUG("actor_node_process", "Actor node process @%d\n", ah->ah_nodeid);

		if(test_and_clear_bit(ACTOR_NODE_INIT, &ah->ah_flags))
			actor_node_init_actors(ah);

		/*Attach all waiters*/
		ATTACH_NODE_QUEUE(ah, ah_queue_wait);

		node_processed = __actor_node_process(ah);

		might_sleep();
	}

    return node_processed;
}

/** 
 * Actor's kthread
 */
int actor_kthread_exec(struct actor_head* ah) {
	/*Sleep until somebody will dispatch us*/
	while(!test_and_clear_bit(ACTOR_NODE_DISPATCHED, &(ah->ah_flags)) &&
			!test_bit(ACTOR_NODE_STOP, &(ah->ah_flags)))
		schedule_timeout(HZ / 10);

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
