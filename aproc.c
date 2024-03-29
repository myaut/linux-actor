#include <actor.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static struct proc_dir_entry* aproc_root;
static struct proc_dir_entry* aproc_alocktm;

#ifdef CONFIG_ACTOR_LOCK_TIMING
extern DEFINE_ALOCK_TIMING(alock_message);
extern DEFINE_ALOCK_TIMING(alock_amutex);
extern DEFINE_ALOCK_TIMING(alock_node);
extern DEFINE_ALOCK_TIMING(alock_work);

static int aproc_locktm_show(struct seq_file* sf, void* v) {
	seq_printf(sf, "Message queue (SPINLOCK): %ld %ld\n", alock_message.busy, alock_message.count);
	seq_printf(sf, "Actor (MUTEX): %ld %ld\n", alock_amutex.busy, alock_amutex.count);
	seq_printf(sf, "Node head (SPINLOCK): %ld %ld\n", alock_node.busy, alock_node.count);
	seq_printf(sf, "Work (SPINLOCK): %ld %ld\n", alock_work.busy, alock_work.count);

	return 0;
}

static int aproc_locktm_open(struct inode *inode, struct file *file) {
	return single_open(file, aproc_locktm_show, PDE(inode)->data);
}

static const struct file_operations aproc_locktm_fops = {
	.open		= aproc_locktm_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

/*
 * Common actor-procfs routines
 * */
void aproc_init(void) {
	aproc_root = proc_mkdir("actor", NULL);

#ifdef CONFIG_ACTOR_LOCK_TIMING
	aproc_alocktm = proc_create_data("lock_timing", S_IRUGO, aproc_root,
										 &aproc_locktm_fops, NULL);
#endif
}

void aproc_exit(void) {
#ifdef CONFIG_ACTOR_LOCK_TIMING
	remove_proc_entry("lock_timing", aproc_root);
#endif

	remove_proc_entry("actor", NULL);
}



/*
 * Routines for actor heads
 * */
static int aproc_head_show(struct seq_file* sf, void* v) {
	struct actor_head* ah = (struct actor_head*) sf->private;

	seq_printf(sf, "Node: %d\n", ah->ah_nodeid);

	seq_puts(sf, "Flags: ");
	if(ah->ah_flags & (1 << ACTOR_NODE_DISPATCHED))
		seq_puts(sf, "dispatched,");
	if(ah->ah_flags & (1 << ACTOR_NODE_INIT))
		seq_puts(sf, "init actors,");
	if(ah->ah_flags & (1 << ACTOR_NODE_MIGRATE))
		seq_puts(sf, "migrate actors,");
	if(ah->ah_flags & (1 << ACTOR_NODE_STOP))
		seq_puts(sf, "stopped");
	seq_puts(sf, "\n");

	return 0;
}

static int aproc_head_open(struct inode *inode, struct file *file) {
	return single_open(file, aproc_head_show, PDE(inode)->data);
}

static const struct file_operations aproc_head_fops = {
	.open		= aproc_head_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

int aproc_create_head(struct actor_head* ah) {
	snprintf(ah->ah_proc_name, APROC_HEAD_NAMELEN, "node-%d", ah->ah_nodeid);

	ah->ah_proc_entry = proc_create_data(ah->ah_proc_name, S_IRUGO, aproc_root,
										 &aproc_head_fops, (void*) ah);

	return 0;
}

void aproc_free_head(struct actor_head* ah) {
	remove_proc_entry(ah->ah_proc_name, aproc_root);
}

/*
 * Routines for actors
 * */

const char* aproc_actor_state_str(actor_state_t state) {
	switch(state) {
	case AS_NOT_INITIALIZED:
		return "NOT_INIT";
	case AS_STOPPED:
		return "STOP";
	case AS_RUNNABLE:
		return "RUN";
	case AS_RUNNABLE_INCOMPLETE:
		return "RUN(I)";
    case AS_FROZEN:
        return "FRO";
	case AS_EXECUTING:
		return "EXC";
	}

	return "?";
}

static int aproc_actor_show(struct seq_file* sf, void* v) {
	actor_t* ac = (actor_t*) sf->private;

	seq_printf(sf, "ID: %lld\n", ac->a_uid);
	seq_printf(sf, "Name: %s\n", ac->a_name);
	seq_printf(sf, "Address: %p\n", ac);
	seq_printf(sf, "Node: %d\n", ac->a_nodeid);
	seq_printf(sf, "State: %s\n", aproc_actor_state_str(ac->a_state));
	seq_printf(sf, "Priority: %d\n", ac->a_prio);
	seq_printf(sf, "Last executed: %ld\n", ac->a_jiffies);

	seq_printf(sf, "Default exec: %p\n", ac->a_exec);

	return 0;
}

static int aproc_actor_open(struct inode *inode, struct file *file) {
	return single_open(file, aproc_actor_show, PDE(inode)->data);
}

static const struct file_operations aproc_actor_fops = {
	.open		= aproc_actor_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

int aproc_create_actor(actor_t* ac) {
	char head_link[APROC_HEAD_NAMELEN + 3];

	snprintf(head_link, APROC_HEAD_NAMELEN + 3, "../node-%d", ac->a_nodeid);
	snprintf(ac->a_proc_name, APROC_ACTOR_NAMELEN, "%s-%lld", ac->a_name, ac->a_uid);

	ac->a_proc_dir = proc_mkdir(ac->a_proc_name, aproc_root);

	proc_create_data("info", S_IRUGO, ac->a_proc_dir,
					 &aproc_actor_fops, (void*) ac);
	proc_symlink("node", ac->a_proc_dir, head_link);

	return 0;
}

void aproc_free_actor(actor_t* ac) {
	remove_proc_entry("info", ac->a_proc_dir);
	remove_proc_entry("node", ac->a_proc_dir);

	remove_proc_entry(ac->a_proc_name, aproc_root);
}


