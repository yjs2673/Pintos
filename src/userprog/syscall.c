#include "userprog/syscall.h"
#include "userprog/process.h"
#include <syscall-nr.h>
#include <stdio.h>
#include <string.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "vm/mmap.h"
struct lock access_lock;
static void syscall_handler (struct intr_frame *);

/* Initialize the system call handler. That means is should be called
   in 'threads/init.c' file to make this handler to be attached to
   the main function of the pintOS. 
   Meanwhile, note that it intializes a mutex lock 'access_lock', that
   provides a synchronization among multiple threads who try to access
   the file system via system calls. You know, this mutex lock is also
   used in the mmap management and the process management. */
void
syscall_init (void) 
{
  lock_init (&access_lock);
  //printf("DEBUG: access_lock address is %p\n", &access_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* System call handler of this pintOS. It uses the stack pointer to
   get arguments for each call. Note that it has the system call
   table to react to users' requests. You can see more detail in the
   report PDF file of the project 1-2 phase. (especially, in 1) */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *esp = f->esp;
  uint32_t sys_num = *esp;
  
  /* System Call Table: Call a corresponding routine
     to perform system function requested by user program. */
  switch (sys_num)
  {
  case SYS_HALT:        /* Halt the operating system. */
      halt ();
      break;

  case SYS_EXIT:        /* Terminate the process. */
      USER_ADDR_CHECK(1, esp);
      exit (ARG(1, int));
      break;

  case SYS_EXEC:        /* Start another process. */
      USER_ADDR_CHECK(1, esp);
      f->eax = exec (ARG(1, char *));
      break;

  case SYS_WAIT:        /* Wait for a child process to die. */
      USER_ADDR_CHECK(1, esp);
      f->eax = wait (ARG(1, pid_t));
      break;

  case SYS_CREATE:      /* Create a file. */
      USER_ADDR_CHECK(2, esp);
      f->eax = create (ARG(1, char *), ARG(2, unsigned));
      break;

  case SYS_REMOVE:      /* Delete a file. */
      USER_ADDR_CHECK(1, esp);
      f->eax = remove (ARG(1, char *));
      break;

  case SYS_OPEN:        /* Open a file. */
      USER_ADDR_CHECK(1, esp);
      f->eax = open (ARG(1, char *));
      break;

  case SYS_FILESIZE:    /* Obtain a file's size. */
      USER_ADDR_CHECK(1, esp);
      f->eax = filesize (ARG(1, int));
      break;

  case SYS_READ:        /* Read from a file. */
      USER_ADDR_CHECK(3, esp);
      f->eax = read (ARG(1, int), ARG(2, void *), ARG(3, unsigned));
      break;

  case SYS_WRITE:       /* Write to a file. */
      USER_ADDR_CHECK(3, esp);
      f->eax = write (ARG(1, int), ARG(2, void *), ARG(3, unsigned));
      break;

  case SYS_SEEK:        /* Change position in a file. */
      USER_ADDR_CHECK(2, esp);
      seek (ARG(1, int), ARG(2, unsigned));
      break;

  case SYS_TELL:        /* Report current position in a file. */
      USER_ADDR_CHECK(1, esp);
      f->eax = tell (ARG(1, int));
      break;

  case SYS_CLOSE:       /* Close a file. */
      USER_ADDR_CHECK(1, esp);
      close (ARG(1, int));
      break;

  case SYS_FIBONACCI:   /* Calculate the N-th fibonacci number. */
      USER_ADDR_CHECK(1, esp);
      f->eax = fibonacci (ARG(1, int));
      break;

  case SYS_MAXOFFOUR:   /* Calculate the maximum among four integers. */
      USER_ADDR_CHECK(4, esp);
      f->eax = max_of_four_int (ARG(1, int), ARG(2, int), ARG(3, int), ARG(4, int));
      break;
  
  case SYS_MMAP:        /* Map a file into memory. */
      USER_ADDR_CHECK(2, esp);
      f->eax = mmap (ARG(1, int), ARG(2, void *));
      break;

  case SYS_MUNMAP:      /* Remove a memory mapping. */
      USER_ADDR_CHECK(1, esp);
      munmap (ARG(1, mapid_t));
      break;

  default: break;
  }
}

void check_user_buffer(const void *buffer, unsigned size, bool to_write) {
    if (buffer == NULL) exit(-1);
    
    char *ptr = (char *)buffer;
    for (unsigned i = 0; i < size; i += 4096) { 
        void *addr = ptr + i;
        POINTER_CHECK(addr); 
        
        // 락 잡기 전에 미리 찔러서 Page Fault 처리!
        if (to_write) {
             volatile char c = *(char *)addr; 
        } else {
             *(char *)addr = *(char *)addr; 
        }
    }
    POINTER_CHECK(ptr + size - 1);
    if (to_write) { volatile char c = *(ptr + size - 1); }
    else { *(ptr + size - 1) = *(ptr + size - 1); }
}

/* Halt routine: it terminates the pintOS via shutdown func. */
void 
halt (void) 
{
  shutdown_power_off ();
}

/* Exit routine: stores an exit status of running thread, with closing all 
   the not-closed files in the FDT. After that, reaps every child process 
   that this current process forked and calls 'thread_exit' to do the main 
   thread-clearing job. */
void 
exit (int status) 
{
  struct file **f_list;
  struct list *c_list;
  struct list_elem *iter;
  int i;

  printf("%s: exit(%d)\n", thread_name (), status);
  thread_current ()->exit_status = status;
  
  /* Close all the not-closed files in the FDT. */
  f_list = &(thread_current ()->fd);
  for (i = 0; i < FD_MAX; i++)
   {
     if (f_list[i] != NULL)
       close (i);
   }

  /* Reap every child process that this(parent) process forked. */
  c_list = &(thread_current ()->child_list);
  for (iter = list_begin (c_list);
      iter != list_end (c_list);
      iter = list_next (iter))
    wait(list_entry(iter, struct thread, child_elem)->tid);
    
  thread_exit ();
}

/* Exec routine: simply calls 'process_execute'. 
   'process_execute' will do the main 'execution' job! */
tid_t 
exec (const char *cmd_line) 
{
  return process_execute (cmd_line);
}

/* Wait routine: simply calls 'process_wait'. */
int 
wait (tid_t pid) 
{
  return process_wait (pid);
}

/* Create routine: checks the value of pointer variable and simply calls 
   'filesys_create' func of filesys.h. Note that all the file-related system 
   calls including this must be synchronized via mutex lock 'access_lock'. */
bool
create (const char *file, unsigned initial_size)
{
  bool success;

  POINTER_CHECK(file);

  lock_acquire (&access_lock);
  success = filesys_create (file, initial_size);
  lock_release (&access_lock);

  return success;
}

/* Remove routine: implemented just like 'create' above. */
bool
remove (const char *file)
{
  bool success;

  POINTER_CHECK(file);

  lock_acquire (&access_lock);
  success = filesys_remove (file);
  lock_release (&access_lock);

  return success;
}

/* Open routine: opens the corresponding file structure of the target file, 
   with assigning a proper descriptor. We should guarantee two things here.
    - only one process at a time can access this code. 
    - if a file is as same as the running program, then deny any write 
      operations on that file.                                           */
int
open (const char *file)
{
  struct file **fd_list;
  struct file *f;
  int i, idx;

  POINTER_CHECK(file);
  lock_acquire (&access_lock);

  /* Open 'open file table' of the input file. 
     If open fails, then return with -1 status */
  f = filesys_open (file);
  if (f == NULL)
   {
     lock_release (&access_lock);
     return OPEN_FILE_ERROR;
   }

  /* If a file is as same as the running program,
     then deny any write operations on this file */
  if (!strcmp (thread_name (), file))
    file_deny_write (f);

  /* Assign proper file descriptor to file struct */
  fd_list = &(thread_current ()->fd);
  for (i = 3; i < FD_MAX; i++) 
   {
     if (fd_list[i] == NULL)
      {
        fd_list[i] = f;
        idx = i;
        break;
      }
   }
  if (i == FD_MAX)
  {
    file_close(f);
    lock_release (&access_lock);
    return OPEN_FILE_ERROR;
  }
  lock_release (&access_lock);

  return idx;
}

/* Filesize routine: simply calls 'file_length' function. */
int
filesize (int fd)
{
  struct file *f;
  int size;

  lock_acquire (&access_lock);

  if (fd < 3 || fd >= FD_MAX) exit (-1);
  f = thread_current ()->fd[fd];
  if (f == NULL) 
  {
    lock_release (&access_lock);
    exit (-1);
  }
  else size = file_length(f);

  lock_release (&access_lock);

  return size;
}

/* Read routine: reads 'size' bytes from the file pointed by fd, and stores 
   it to buffer. We should guarantee one thing below. (same for the next 
   'write' routine)
    - only one process at a time can access this code. */
int 
read (int fd, void *buffer, unsigned size)
{
  check_user_buffer(buffer, size, true);
  struct file *f;
  off_t byte_cnt = 0; 
  char c; unsigned i;

  POINTER_CHECK(buffer);
  lock_acquire (&access_lock);
    
  if (fd == 0) 
   {   /* STDIN_FILENO */
     for (i = 0; (i < size) && ((c = input_getc()) != '\0'); i++)
      {
        *((char*)buffer) = c;
        buffer = (char*)buffer + 1;
        byte_cnt++;
      }
     *((char*)buffer) = '\0';
   }
  else if (fd < 3 || fd >= FD_MAX)
   {   /* File descriptor error */
     lock_release (&access_lock);
     exit (-1);
   }
  else 
   {   /* Any I/O-possible files */
     f = thread_current ()->fd[fd];
     if (f == NULL)
      {
        lock_release (&access_lock);
        exit (-1);
      }
        
     byte_cnt = file_read (f, buffer, size);
   }
  lock_release (&access_lock);

  return byte_cnt;
}

/* Write routine: writes 'size' bytes of buffer to the file pointed by fd. 
   We should guarantee two things here.
    - only one process at a time can access this code. 
    - if a file is as same as the running program, then deny any write 
      operations on that file.                                          */
int 
write (int fd, const void *buffer, unsigned size) 
{
  check_user_buffer(buffer, size, true);
  struct file *f;
  off_t byte_cnt = 0;

  POINTER_CHECK(buffer);
  lock_acquire (&access_lock);

  if (fd == 1) 
   {   /* STDOUT_FILENO */
     putbuf(buffer, size);
     byte_cnt += size;
   }
  else if (fd < 3 || fd >= FD_MAX)
   {   /* File descriptor error */
     lock_release (&access_lock);
     exit (-1);
   }
  else 
   {   /* Any I/O-possible files */
     f = thread_current ()->fd[fd];
     if (f == NULL)
      {
        lock_release (&access_lock);
        exit (-1);
      }
     if (f->deny_write == true)
       file_deny_write (f);

     byte_cnt = file_write (f, buffer, size);
   }
  lock_release (&access_lock);

  return byte_cnt;
}

/* Seek routine: simply calls 'file_seek' function. This is implemented 
   just like the 'filesize' syscall. Same for the 'tell' syscall below. 
   (The reason why these are implemented simply is that pintOS provides 
   the complete basic file system with filesys.h) */
void
seek (int fd, unsigned position)
{
  struct file *f;

  lock_acquire (&access_lock);

  if (fd < 3 || fd >= FD_MAX) exit (-1);
  f = thread_current ()->fd[fd];
  if (f == NULL) 
  {
    lock_release (&access_lock);
    exit (-1);
  }

  file_seek (f, position);

  lock_release (&access_lock);
}

/* Tell routine: simply calls 'file_tell' function. */
unsigned
tell (int fd)
{
  struct file *f;
  unsigned pos;

  lock_acquire (&access_lock);

  if (fd < 3 || fd >= FD_MAX) exit (-1);
  f = thread_current ()->fd[fd];
  if (f == NULL) 
  {
    lock_release (&access_lock);
    exit (-1); 
  }

  pos = file_tell(f);

  lock_release (&access_lock);

  return pos;
}

/* Close routine: simply calls 'file_close' function. */
void
close (int fd)
{
  struct file *f;

  if (fd < 3 || fd >= FD_MAX) exit (-1);
  f = thread_current ()->fd[fd];
  if (f == NULL) exit (-1);

  thread_current ()->fd[fd] = NULL;

  file_close (f);
}

/* Fibonacci routine: returns N-th value of fibonacci sequence.
   It produces sequence with simple iterative algorithm. */
int 
fibonacci (int n) 
{
  int f = 0, f1 = 1, f2 = 0;
  int i;

  if (n == 0) return 0;
  if (n == 1) return 1;
  for (i = 2; i <= n; i++) 
   {
     f = f1 + f2;
     f2 = f1;
     f1 = f;
   }

  return f;
}

/* Max_of_four_int routine: returns the maximum among arbitrary decimals.
   It uses simple bubble-sort to figure out the maximum. */
int 
max_of_four_int (int a, int b, int c, int d)
{
  int arr[4], temp;
  int i, j;

  arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
  for (i = 0; i < 3; i++) 
    for (j = i + 1; j < 4; j++) 
     {
       if (arr[i] > arr[j]) 
        {
          temp = arr[i];
          arr[i] = arr[j];
          arr[j] = temp;
        }
     }

  return arr[3];
}

/* Mmap routine: simply calls the function 'mm_mapping' that performs a 
   memory mapping. Yes, this function is declared in 'vm/mmap.h' file. */
mapid_t
mmap (int fd, void *addr)
{
  return mm_mapping (fd, addr);
}

/* Munmap routine: simply calls the function 'mm_freeing' just like the
   mmap() above, and of course, it's declared in 'vm/mmap.h' file. */
void 
munmap (mapid_t mapid)
{
  mm_freeing (mapid);
}
