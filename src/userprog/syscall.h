#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"

/* Here are procedures for every system calls this pintOS provides. 
   In the project 1-2 phases, we construct the whole system that can
   properly provides each system call to user processes. 
   
   In the project 4 phase, we construct the mmap() and munmap() syscalls
   to implement a memory mapping concepts for a successful lazy loading
   mechanisms of this pintOS. 
   
   Note that wrappers for system calls are declared in 'lib/user/syscall.h',
   and the system call numbers are declared in 'lib/syscall-nr.h'. 
   This header provides the main part that actually perform the operations.
   Read carefully comments for each system call. */

#define bool	_Bool

void syscall_init (void);

/* Macro functions for forming an argument that will be passed to syscall. 
   - ARG_ADDR: returns the address of given passed-by-syscall arguments. 
   - ARG: returns the value of given pointer, by casting of 'type'.      */
#define ARG_ADDR(k) ((uint8_t*)esp + 4*k)
#define ARG(k, type) *(type*)(ARG_ADDR(k))

/* Macro functions for checking passing arguments of syscall. 
   - POINTER_CHECK: checks if an argument is in the user address space 
     with pre-provided 'is_user_vaddr' function. And, check NULL also!   
   - STACK_CHECK: checks if there's no mapping page for the current virtual
     address, then try to expand the user stack if it's possible! That means
     this macro should be called for each argument passing of syscall.
   - USER_ADDR_CHECK: checks all the parameters that a system call needs
     with consequtively calling 'POINTER_CHECK' macro above!             */
#define POINTER_CHECK(vaddr) if (vaddr == NULL || is_user_vaddr (vaddr) == false) exit (-1);
#define STACK_CHECK(vaddr, esp) if(!pt_find_entry (vaddr)) { if (!expand_stack (vaddr, esp)) exit (-1); }  
#define USER_ADDR_CHECK(param_num, esp) for(int i=1;i<=param_num;i++){POINTER_CHECK(ARG_ADDR(i)); STACK_CHECK(ARG_ADDR(i), esp); }

/* Process Identifier type. */
typedef int pid_t;

/* Mapping Identifier type. */
typedef unsigned mapid_t;

/* Binary semaphore providing the mutual 
   exclusion while accessing the file system. */
extern struct lock access_lock;

/* It indicates that an error occurs in the 'open' syscall. */
#define OPEN_FILE_ERROR -1

/* Routines to perform each system call functionality. */
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int fibonacci (int n);
int max_of_four_int (int a, int b, int c, int d);
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapid);

#endif /* userprog/syscall.h */
