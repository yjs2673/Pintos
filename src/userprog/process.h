#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"

/* The core of this pintOS system, that is, it's about creation
   and termination, and sleeping of user-side processes. 

   Therefore, this file is the main battlefield of the project 1-2
   and 4 phase, which requires passing of pintOS user program tests. 
   
   You can see a sophisticated description in comments of each func
   in 'process.c' file and the attached reports in each phase. */

/* Maximum number of arguments(bytes). */
#define MAX_ARGS 128

/* Maximum size of the stack segment. */
#define MAX_STACK_SIZE 0x8000000

/* Process management functions. */

int process_wait (tid_t);
tid_t process_execute (const char *file_name);
void process_activate (void);
void process_exit (void);

/* Page Fault Handling procedures. */
bool handle_mm_fault (struct pt_entry *pte);
bool expand_stack (void *addr, void *esp);

#endif /* userprog/process.h */
