/**
 * Linux actor subsystem
 * Hardware topology level
 * 
 * Copyright (c) Sergey Klyaus, 2011
 */

#ifndef __HWTOPO_H
#define __HWTOPO_H

#include <asm/smp.h>
#include <linux/smp.h>
#include <linux/cpu.h>

/*Stub*/
#define HWTOPO_NODE_ISLOCAL(nodeid)     (nodeid == smp_processor_id())
#define HWTOPO_NODE_CORRECT(nodeid) 	(nodeid >= 0 && nodeid < NR_CPUS)

#define HWTOPO_FOR_EACH_NODE(idx)		for_each_online_cpu(idx)

#endif
