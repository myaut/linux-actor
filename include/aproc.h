/**
 * Linux actor subsystem
 * Actor-procfs bridge helper functions
 *
 * Copyright (c) Sergey Klyaus, 2011-2012
 */

#ifndef APROC_H
#define APROC_H

int aproc_init(void);
int aproc_exit(void);

int aproc_create_head(struct actor_head* ah);
void aproc_free_head(struct actor_head* ah);

int aproc_create_actor(actor_t* ac);
void aproc_free_actor(actor_t* ac);

#endif
