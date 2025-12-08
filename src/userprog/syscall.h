#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include <stdbool.h>
#include <stdint.h>
#include "threads/synch.h"

extern struct lock filesys_lock;

void syscall_init (void);

#endif /* userprog/syscall.h */
