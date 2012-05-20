/**
 * Linux actor subsystem
 *
 * Copyright (c) Sergey Klyaus, 2011-2012
 */

#ifndef ACTOR_H
#define ACTOR_H

#include <linux/types.h>
//#include <linux/config.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/timer.h>
#include <linux/clocksource.h>
#include <linux/semaphore.h>
#include <linux/wait.h>

//#define CONFIG_ACTOR_TRACE
//#define CONFIG_ACTOR_DEBUG
#define CONFIG_ACTOR_LOCK_TIMING

/* Maximum number of asynchronious communications
 * that are processed simultaneously*/
#define CONFIG_ACTOR_MAX_QLEN	1024
/* Number of free slots when sender selects
 * slowpath for actor_communicate_async*/
#define ACTOR_QLEN_THRESHOLD 	(4 * num_online_cpus())
/* Number of busy slots when actor desides to wakeup sleeping threads
 */
#define ACTOR_WAKEUP_THRESHOLD	ACTOR_QLEN_THRESHOLD

/*Actor debug routine*/
#ifdef CONFIG_ACTOR_TRACE
#	define ADEBUG(name, format, ...) __actor_trace(name, format, __VA_ARGS__); \
									 ;  printk(KERN_INFO "@%d " name ": " format, smp_processor_id(), __VA_ARGS__);
#	define A_NOINLINE	noinline
#else
#	define ADEBUG(name, format, ...)
#	define A_NOINLINE	noinline
#endif

#ifdef CONFIG_ACTOR_LOCK_TIMING
struct alock_timing {
	unsigned long count;
	unsigned long busy;
};

#define DEFINE_ALOCK_TIMING(name) \
		struct alock_timing name

#define DECLARE_ALOCK_TIMING(name) \
		DEFINE_ALOCK_TIMING(name) = { 0UL , 0UL }

#endif

#define ANAMEMAXLEN     16
#define AMAXPIPELINE    8
#define AMAXCOMM		32

#define APROC_HEAD_NAMELEN	 	18
#define APROC_ACTOR_NAMELEN		21 + ANAMEMAXLEN + 1

struct actor;
typedef struct actor actor_t;

struct actor_work;
typedef struct actor_work actor_work_t;

/* Return values of actor callback*/
#define 	ACTOR_SUCCESS		   0
#define 	ACTOR_INCOMPLETE	   1
#define		ACTOR_INCOMPLETE_STAGE 2

/**
 * Actor callback function */
typedef int (*actor_callback)(struct actor* self, actor_work_t* work);

typedef struct actor_exec {
	actor_callback	ae_pipeline[AMAXPIPELINE];
} actor_exec_t;

/*FIXME: Doesn't work for eight callbacks*/
#define DECLARE_ACTOR_EXEC(name, ...)  actor_exec_t name = {	\
				.ae_pipeline = {__VA_ARGS__, 0}					\
			};

/*
 * Actor message format.
 * Like L4 we have typed and untyped words, but we
 * work in shared memory so we have simpler serialization protocol.
 * 
 * +--------+
 * | Header |
 * +--------+
 * | untyped|
 * |  ...   |
 * |        |
 * +--------+
 * | typed  |
 * |        |
 * |        |
 * +--------+
 * 
 */

typedef unsigned long amsg_word_t;
typedef struct {
    void* ptr;
    u32   sz;
} amsg_typed_t;

/*Header for actor request*/ 
struct amsg_hdr {
    atomic_t		  am_count;		/*Reference count*/

    actor_exec_t* 	  am_exec;

    u16				  am_untyped_num;
    u16				  am_typed_num;
    amsg_word_t 	  am_result;
    amsg_word_t       am_untyped[0];
};
typedef struct amsg_hdr amsg_hdr_t;

#define AMSG_UNTYPED_NUM(amsg)       ((unsigned long) (amsg)->typed - (unsigned long) (amsg)->untyped) / sizeof(amsg_word_t)
#define AMSG_TYPED_NUM(amsg)         (((unsigned long) amsg) + amsg->len - (unsigned long) amsg->typed) / sizeof(amsg_typed_t)

/*
 * Actor main structure
 * 
 */


typedef int (*actor_ctor)(actor_t* self, void* data);
typedef int (*actor_dtor)(actor_t* self);



#define     ACTOR_MAGIC         0xAC10930D

#ifdef CONFIG_ACTOR_DEBUG
#define ACTOR_MAGIC_CHECK(ac)   \
    BUG_ON(!ac || (ac)->a_magic != ACTOR_MAGIC)
#define ACTOR_CHECK(cond) 	BUG_ON(cond)
#else 
#define ACTOR_MAGIC_CHECK(ac)
#define ACTOR_CHECK(cond)
#endif


typedef enum {
	AS_NOT_INITIALIZED,         /*Actor is not yet initialized*/
    AS_STOPPED,                 /*No works for this actor*/
    AS_RUNNABLE,                /*There are new works on queues*/
	AS_RUNNABLE_INCOMPLETE,     /*There are incompleted works on queue*/
	AS_EXECUTING,               /*Actor is on node*/
    AS_FROZEN                   /*Actor is frozen before destroying. 
                                  Doesn't accept new messages. */
} actor_state_t;

/*Check for any of RUNNABLE flags*/
#define ACTOR_IS_RUNNABLE(astate)                   \
           ( astate == AS_RUNNABLE ||               \
             astate == AS_RUNNABLE_INCOMPLETE ||    \
             astate == AS_FROZEN )

#define AW_NONE				0x0

#define AW_BLOCKING 		0x1
#define AW_ATOMIC			0x2
#define AW_COMMUNICATING	0x4
#define AW_ASYNCHRONOUS 	0x8

#define AW_COMM_START		0x10
#define AW_COMM_COMPLETE	0x20

#define AW_EXECUTING		0x100
#define AW_REDISPATCHED		0x200
#define AW_FINISHED			0x400


/*
 * Actor work is queue of messages which actor has to process.
 * 
 */

#ifdef CONFIG_ACTOR_DEBUG
#define AWORK_HIST_LEN		32
#define AWORK_HIST_ADD_2(aw, op, arg)							\
	{ long hi = atomic_inc_return(&aw->aw_hist_index);			\
	if(hi < AWORK_HIST_LEN) {   								\
		aw->aw_hist[hi].h_op = op;								\
		aw->aw_hist[hi].h_ret_ip = _RET_IP_;					\
		aw->aw_hist[hi].h_comm =  current->comm;				\
		aw->aw_hist[hi].h_flags = aw->aw_flags;					\
	} }															\

#define AWORK_HIST_ADD(aw, op) AWORK_HIST_ADD_2(aw, op, 0UL)
#else
#define AWORK_HIST_ADD2(aw, op, arg)
#define AWORK_HIST_ADD(aw, op)
#endif

struct actor_work {
    actor_t*    aw_actor;
    amsg_hdr_t* aw_msg;
    
    spinlock_t	aw_lock;				/*Protects aw_flags*/
    struct list_head aw_list;

    struct completion aw_wait;			/*Waiter completion for external threads*/

    atomic_t aw_count;					/*Count of referencing waiters*/
    struct actor_work* aw_wait_work;	/*Blocked work*/
    u8 		aw_ww_comm;					/*ID of comm in blocked work*/

    union {
    	struct {
    		/*FIXME: Endianess!*/
    		u16 aw_misc_flags;

    		u8 aw_comm_count;			/*Number of incomplete inter-actor communications*/
			u8 aw_pipe_count;			/*Number of pipeline callbacks processed*/

			u32 aw_comm_flags;
    	};
    	u64 aw_flags;
    };

#ifdef CONFIG_ACTOR_DEBUG
    actor_work_t* aw_last_comm;

	struct {
		char h_op;				 /*Operation (HOLD/RELE)*/
		unsigned long h_ret_ip;  /*_RET_IP_ value*/
		char* h_comm;	 		 /*Current task's name*/
		u64   h_flags;			 /*aw->aw_flags*/
	} aw_hist[AWORK_HIST_LEN];
	atomic_t aw_hist_index;
#endif
};

#define AWORK_MESSAGE(ac, cpu)	ac->a_work_message[cpu]
#define AWORK_MESSAGE_THIS(ac)	AWORK_MESSAGE(ac, smp_processor_id())

struct actor {
#   ifdef CONFIG_ACTOR_DEBUG
    unsigned long a_magic;
#   endif    

    struct mutex a_mutex;		/* Protects a_state and a_list */
    
	int a_nodeid;
	u64 a_uid;
	char a_name[ANAMEMAXLEN];

	u16	a_flags;
	u16 a_prio;					/*Actor priority*/

	actor_state_t a_state;				
	
	struct list_head a_list;			/*Per-node actor list*/
	struct list_head a_acquaintance;	/*Actor acquaintances for
										building actor topology*/
	
	actor_ctor a_ctor;
	actor_dtor a_dtor;

	actor_exec_t* a_exec;
	
	struct task_struct* a_proc;			/*Associated process*/

    atomic_t			a_qlen;
    long				a_max_qlen;
    wait_queue_head_t	a_queue_wq;

	struct list_head    a_work_active;  /*Work queue which is currently processed*/

	struct {
		spinlock_t       lock;
		struct list_head queue;
	} a_work_message[NR_CPUS];			/*One queue per cpu*/

	struct completion   a_destroy_wait; /*Wait until actor completes all it's works*/

	unsigned long		a_jiffies;		/*Last actor execution mark*/

	void*				a_private_temp;
	void* 			    a_private;		/*Private section that holds actor data*/
	unsigned long		a_private_len;

	struct proc_dir_entry* a_proc_dir;
	char a_proc_name[APROC_ACTOR_NAMELEN];
};

enum actor_head_flag {
	ACTOR_NODE_DISPATCHED,	/* Actors are dispatched on this node*/
	ACTOR_NODE_INIT,		/* There are uninitialized actors on this node*/
	ACTOR_NODE_MIGRATE,		/* There are actors that need to complete migration*/

	ACTOR_NODE_STOP,		/*Node is stopped*/
	ACTOR_NODE_WAIT			/*There are waiters on node*/
};

/*Per-node actor list*/
struct actor_head {
	spinlock_t  ah_lock;			/*Protects queues except INIT/MIGR queues*/
    spinlock_t  ah_lock_init;		/*Protects INIT queue*/

	int		ah_nodeid;				/*Node number*/

	struct list_head ah_queue_exec;		/*List for per-cpu actor*/
	struct list_head ah_queue_init;  /*List of actors which doesn't initialized yet
	 	 	 	 	 	 	 	 	 New actors may only attach to this queue*/
	struct list_head ah_queue_migr;  /*List of actors which was attached to this
	 	 	 	 	 	 	 	 	 node during migration and doesn't migrate their
	 	 	 	 	 	  	 	 private data*/

	struct list_head ah_queue_stop;	 /*Actors that stopped execution because they are processed
	 	 	 	 	 	 	 	 	   their messages*/
	struct list_head ah_queue_wait;	 /*Actors that incompleted execution (i.e. due to slice exhaustion
	 	 	 	 	 	 	 	 	 waiting next cycle in this queue*/

	unsigned ah_num_actors;			/*Number of actors attached to this node*/

	unsigned long ah_flags;

	struct task_struct* ah_kthread;
	struct completion ah_wait;		/*Thread completion*/

	struct proc_dir_entry* ah_proc_entry;
	char ah_proc_name[APROC_HEAD_NAMELEN];

	struct timer_list ah_timer;
};

actor_t* actor_create(u32 flags, u32 prio, int nodeid, char* name,
			actor_ctor ctor, actor_dtor dtor, actor_exec_t* ae, void* data);

static actor_t* actor_create_simple(u32 flags, u32 prio, int nodeid, char* name,
		actor_exec_t* ae) {
	return actor_create(flags, prio, nodeid, name, NULL, NULL, ae, NULL);
}

void actor_destroy(actor_t* ac);

int actor_communicate(actor_t* ac, amsg_hdr_t* msg);
int actor_communicate_async(actor_t* ac, amsg_hdr_t* msg);
int actor_communicate_blocked(actor_t* ac, amsg_hdr_t* msg);

amsg_hdr_t* amsg_create(u32 untyped_num, u32 typed_num, actor_exec_t* ae, int nodeid);
void amsg_free(amsg_hdr_t* msg);

void* actor_private_allocate(actor_t* ac, unsigned long len);
void actor_private_free(actor_t* ac);

#ifdef CONFIG_ACTOR_TRACE
int actor_trace(char* name, char* fmtstr, ...);
#endif

#endif

