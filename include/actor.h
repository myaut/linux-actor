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

#define CONFIG_ACTOR_TRACE

/*Actor debug routine*/
#ifdef CONFIG_ACTOR_TRACE
#	define ADEBUG(name, format, ...) __actor_trace(name, format, __VA_ARGS__); \
									 ; printk(KERN_INFO "@%d " name ": " format, smp_processor_id(), __VA_ARGS__);
#	define A_NOINLINE	noinline
#else
#	define ADEBUG(name, format, ...)
#	define A_NOINLINE	noinline
#endif

#define ANAMEMAXLEN     16
#define AMAXPIPELINE    8

#define APROC_HEAD_NAMELEN	 	18
#define APROC_ACTOR_NAMELEN			21 + ANAMEMAXLEN + 1

/*
 * Actor message format.
 * Like L4 we have typed and untyped words, but we
 * work in shared memory so we have simpler serialization protocol.
 * 
 * +--------+
 * | HDR:   |
 * | len    | 
 * | untyped|--+
 * | typed  |--|--+
 * +--------+<-+  |
 * |  ...   |     |
 * |        |     |
 * +--------+<----+
 * |  ...   |
 * |        |
 * |        |
 * +--------+
 * 
 * number of untyped items = ((char*) typed - (char*) untyped) / sizeof(amsg_word_t)
 * number of typed items = (((char*) msgptr + hdrlen) - (char*) untyped) / sizeof(amsg_typed_t)
 */

typedef unsigned long amsg_word_t;
typedef struct {
    void* ptr;
    u32   sz;
} amsg_typed_t;

/*Header for actor request*/
struct amsg_hdr {
    u32     len;
    
    amsg_word_t      result;
    amsg_word_t*     untyped;
    amsg_typed_t*    typed;
};
typedef struct amsg_hdr amsg_hdr_t;

#define AMSG_UNTYPED_NUM(amsg)       ((unsigned long) (amsg)->typed - (unsigned long) (amsg)->untyped) / sizeof(amsg_word_t)
#define AMSG_TYPED_NUM(amsg)         (((unsigned long) amsg) + amsg->len - (unsigned long) amsg->typed) / sizeof(amsg_typed_t)

/*
 * Actor main structure
 * 
 */

struct actor;
typedef struct actor actor_t;


typedef int (*actor_ctor)(actor_t* self, void* data);
typedef int (*actor_dtor)(actor_t* self);

/* Return values of actor callback
 *
 * NOTE: any non-zero value is treated as incomplete*/
#define 	ACTOR_SUCCESS		0
#define 	ACTOR_INCOMPLETE	1

/**
 * Actor callback function
 * must return 0 if message was processed or 1 if message should be blocked */
typedef int (*actor_callback)(actor_t* self, amsg_hdr_t* msg, int aw_flags);

typedef enum {
	AS_NOT_INITIALIZED,
    AS_STOPPED,
    AS_RUNNABLE,
	AS_RUNNABLE_INCOMPLETE,
	AS_EXECUTING
} actor_state_t;

#define AW_NONE				0x0
#define AW_BLOCKING 		0x1
#define AW_COMMUNICATING	0x2
#define AW_COMM_COMPLETE	0x4

/*
 * Actor work is queue of messages which actor has to process.
 * 
 */
struct actor_work {
    actor_t*    aw_actor;
    amsg_hdr_t* aw_msg;
    
    struct list_head aw_list;

    struct completion aw_wait;	/*Waiter completion for external threads*/

    atomic_t aw_count;					/*Count of referencing waiters*/
    struct actor_work* aw_wait_work;	/*Waiter blocked on actor_int_communicate*/

    int aw_flags;

};
typedef struct actor_work actor_work_t;

struct actor {
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

    union {
        struct {
            actor_callback	pipeline[AMAXPIPELINE];
            u32             len;     
        } a_pipeline;
        
        actor_callback a_function; /*Actor callback*/
    } a_exec;
	
	struct task_struct* a_proc;			/*Associated process*/
	
    spinlock_t          a_msg_lock;      /*Protects message queue*/
	
	struct list_head    a_work_active;  /*Work queue which is currently processed*/
	struct list_head    a_work_message;  /*Work queue to put messages*/
	struct list_head	a_work_waiting;	/*Works waiting for finishing communication*/

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

	struct clocksource* ah_clock;

	struct proc_dir_entry* ah_proc_entry;
	char ah_proc_name[APROC_HEAD_NAMELEN];

	struct timer_list ah_timer;
};

actor_t* actor_create(u32 flags, u32 prio, int nodeid, char* name,
			actor_ctor ctor, actor_dtor dtor, actor_callback f, void* data);

static actor_t* actor_create_simple(u32 flags, u32 prio, int nodeid, char* name,
			actor_callback f) {
	return actor_create(flags, prio, nodeid, name, NULL, NULL, f, NULL);
}


void actor_destroy(actor_t* ac);

int actor_communicate(actor_t* ac, amsg_hdr_t* msg);
int actor_communicate_blocked(actor_t* ac, amsg_hdr_t* msg);

amsg_hdr_t* amsg_create(u32 untyped_num, u32 typed_num, int nodeid);
void amsg_free(amsg_hdr_t* msg);

void* actor_private_allocate(actor_t* ac, unsigned long len);
void actor_private_free(actor_t* ac);

#ifdef CONFIG_ACTOR_TRACE
int actor_trace(char* name, char* fmtstr, ...);
#endif

#endif
