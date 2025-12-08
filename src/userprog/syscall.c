#include "userprog/syscall.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>
#include <stdlib.h>
#include "vm/mmap.h"
#include "vm/page.h"

typedef int pid_t;

void shutdown_power_off (void);             /* devices/shutdown.h */
uint8_t input_getc (void);                  /* devices/input.h */
void putbuf (const char *buffer, size_t n); /* lib/kernel/console.h */

static void syscall_handler (struct intr_frame *);

/* Filesystem serialization lock */
struct lock filesys_lock;

/* 단일 포인터 유효성 검사 */
static void
validate_ptr (const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr (uaddr))
    {
      sys_exit (-1);
    }
}

/* 버퍼 유효성 검사 함수 */
static void
validate_buffer (const void *buffer, unsigned size, bool to_write)
{
  if (size == 0)
    return;

  if (buffer == NULL)
    sys_exit (-1);

  const uint8_t *addr = buffer;
  unsigned offset = 0;

  while (offset < size)
    {
      void *ptr = (void *)(addr + offset);
      
      if (!is_user_vaddr (ptr))
        sys_exit (-1);

      struct pt_entry *vme = pt_find_entry (ptr);
      
      if (vme != NULL)
        {
          if (to_write && !vme->writable)
            sys_exit (-1);
        }
      else
        {
           /* Unmapped memory check (simple) */
           if (pagedir_get_page (thread_current ()->pagedir, ptr) == NULL)
             {
               // 필요시 추가 로직 (스택 확장 등)
             }
        }

      unsigned page_left = PGSIZE - pg_ofs (ptr);
      unsigned advance = page_left < (size - offset) ? page_left : (size - offset);
      offset += advance;
    }
    
    void *end_ptr = (void *)(addr + size - 1);
    if (!is_user_vaddr(end_ptr)) sys_exit(-1);
    
    if (to_write) {
        struct pt_entry *vme = pt_find_entry(end_ptr);
        if (vme != NULL && !vme->writable) sys_exit(-1);
    }
}

/* 문자열 유효성 검사 */
static void
validate_cstr (const char *str)
{
  if (str == NULL) sys_exit(-1);
  validate_ptr (str);
  
  while (*str != '\0')
    {
      str++;
      if (pg_ofs(str) == 0)
        validate_ptr(str);
    }
}

static int32_t
get_user_int (const void *uaddr)
{
  validate_ptr (uaddr);
  validate_ptr (uaddr + 3); 
  return *(const int32_t *) uaddr;
}

/* syscall function definitions */
/*============================================*/
void sys_halt (void)
{
  shutdown_power_off ();
}

void sys_exit (int status)
{
  struct thread *t = thread_current ();
  t->exit_status = status;
  printf ("%s: exit(%d)\n", t->name, status);
  thread_exit ();
}

int sys_wait (pid_t pid)
{
  return process_wait (pid);
}

bool sys_create (const char *file, unsigned initial_size)
{
  validate_cstr(file);
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool sys_remove (const char *file)
{
  validate_cstr(file);
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int sys_open (const char *file)
{
  validate_cstr(file);
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (f == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }

  struct thread *t = thread_current();
  /* 수정: fd_table -> fd */
  for (int i = 2; i < 128; i++)
  {
    if (t->fd[i] == NULL) 
    {
      t->fd[i] = f;
      lock_release(&filesys_lock);
      return i;
    }
  }

  file_close(f);
  lock_release(&filesys_lock);
  return -1;
}

int sys_filesize (int fd)
{
  if (fd < 2 || fd >= 128) return -1;
  
  struct thread *t = thread_current();
  /* 수정: fd_table -> fd */
  struct file *f = t->fd[fd];

  if (f == NULL) return -1;

  lock_acquire(&filesys_lock);
  int size = file_length(f);
  lock_release(&filesys_lock);
  return size;
}

int sys_read (int fd, void *buffer, unsigned size)
{
  validate_buffer(buffer, size, true);

  if (fd == 1) return -1; // STDOUT

  if (fd == 0) {
      uint8_t *buf = (uint8_t *)buffer;
      for (unsigned i = 0; i < size; i++) buf[i] = input_getc();
      return size;
  }

  struct thread *t = thread_current();
  if (fd < 2 || fd >= 128) return -1;
  /* 수정: fd_table -> fd */
  struct file *f = t->fd[fd];
  if (f == NULL) return -1;

  /* 수정: malloc 호출 전 size 0 처리 (read-zero 해결) */
  if (size == 0) return 0;

  void *kbuffer = malloc(size);
  if (kbuffer == NULL) return -1;

  lock_acquire(&filesys_lock);
  int bytes_read = file_read(f, kbuffer, size);
  lock_release(&filesys_lock);

  memcpy(buffer, kbuffer, bytes_read);
  free(kbuffer);

  return bytes_read;
}

int sys_write (int fd, const void *buffer, unsigned size)
{
  validate_buffer(buffer, size, false);

  if (fd == 0) return -1; // STDIN

  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }

  struct thread *t = thread_current();
  if (fd < 2 || fd >= 128) return -1;
  /* 수정: fd_table -> fd */
  struct file *f = t->fd[fd];
  if (f == NULL) return -1;

  /* 수정: malloc 호출 전 size 0 처리 (write-zero 해결) */
  if (size == 0) return 0;

  void *kbuffer = malloc(size);
  if (kbuffer == NULL) return -1;
  memcpy(kbuffer, buffer, size);

  lock_acquire(&filesys_lock);
  int bytes_written = file_write(f, kbuffer, size);
  lock_release(&filesys_lock);

  free(kbuffer);
  return bytes_written;
}

pid_t sys_exec (const char *cmd_line)
{
  validate_cstr(cmd_line);
  return process_execute (cmd_line);
}

/* static으로 변경하여 프로토타입 경고 해결 */
static void sys_seek (int fd, unsigned position)
{
  if (fd < 2 || fd >= 128) return;
  
  struct thread *t = thread_current();
  /* 수정: fd_table -> fd */
  struct file *f = t->fd[fd];

  if (f == NULL) return;

  lock_acquire(&filesys_lock);
  file_seek(f, position);
  lock_release(&filesys_lock);
}

/* static으로 변경하여 프로토타입 경고 해결 */
static unsigned sys_tell (int fd)
{
  if (fd < 2 || fd >= 128) return 0;

  struct thread *t = thread_current();
  /* 수정: fd_table -> fd */
  struct file *f = t->fd[fd];

  if (f == NULL) return 0;

  lock_acquire(&filesys_lock);
  unsigned position = file_tell(f);
  lock_release(&filesys_lock);
  return position;
}

/* static으로 변경하여 프로토타입 경고 해결 */
void sys_close(int fd) {
    if (fd < 2 || fd >= 128) return;
    struct thread *t = thread_current();
    /* 수정: fd_table -> fd */
    if (t->fd[fd] == NULL) return;
    
    lock_acquire(&filesys_lock);
    file_close(t->fd[fd]);
    t->fd[fd] = NULL;
    lock_release(&filesys_lock);
}

/* Additional syscalls */
int sys_fibonacci (int n)
{
  if (n < 0 || n > 46) return -1; 
  int pprev = 0, prev = 1, cur = 0;
  if (n == 0) return pprev;
  if (n == 1) return prev;

  for (int i = 1; i < n; i++)
  {
    cur = prev + pprev;
    pprev = prev;
    prev = cur;
  }
  return cur;
}

int sys_max_of_four_int (int a, int b, int c, int d)
{
  int max1 = a >= b ? a : b;
  int max2 = c >= d ? c : d;
  return max1 >= max2 ? max1 : max2;
}

/*============================================*/

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = f->esp;

  validate_ptr (esp);
  
  int sysno = get_user_int (esp);

  uint32_t arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0;
  
  if (sysno == SYS_HALT || sysno == SYS_EXIT || sysno == SYS_EXEC || 
      sysno == SYS_WAIT || sysno == SYS_CREATE || sysno == SYS_REMOVE ||
      sysno == SYS_OPEN || sysno == SYS_FILESIZE || sysno == SYS_SEEK ||
      sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_TELL ||
      sysno == SYS_CLOSE || sysno == SYS_FIBONACCI || sysno == SYS_MAX_OF_FOUR_INT ||
      sysno == SYS_MMAP || sysno == SYS_MUNMAP)
  {
    if (sysno != SYS_HALT)                
      arg0 = get_user_int ((uint8_t *) esp + 4);
    if (sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_MAX_OF_FOUR_INT ||
        sysno == SYS_CREATE || sysno == SYS_SEEK || sysno == SYS_MMAP)
      arg1 = get_user_int ((uint8_t *) esp + 8);
    if (sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_MAX_OF_FOUR_INT)  
      arg2 = get_user_int ((uint8_t *) esp + 12);
    if (sysno == SYS_MAX_OF_FOUR_INT)             
      arg3 = get_user_int ((uint8_t *) esp + 16);
  }

  switch (sysno)
  {
  case SYS_HALT:
    sys_halt ();
    break;

  case SYS_EXIT:
    sys_exit ((int)arg0);
    break;

  case SYS_EXEC:
    f->eax = (uint32_t) sys_exec ((const char *) arg0);
    break;

  case SYS_WAIT:
    f->eax = (uint32_t) sys_wait ((pid_t) arg0);
    break;

  case SYS_CREATE:
    f->eax = (uint32_t) sys_create ((const char *) arg0, (unsigned) arg1);
    break;

  case SYS_REMOVE:
    f->eax = (uint32_t) sys_remove ((const char *) arg0);
    break;

  case SYS_OPEN:
    f->eax = (uint32_t) sys_open ((const char *) arg0);
    break;

  case SYS_FILESIZE:
    f->eax = (uint32_t) sys_filesize ((int)arg0);
    break;

  case SYS_READ:
    f->eax = (uint32_t) sys_read ((int)arg0, (void *) arg1, (unsigned) arg2);
    break;

  case SYS_WRITE:
    f->eax = (uint32_t) sys_write ((int)arg0, (const void *) arg1, (unsigned) arg2);
    break;

  case SYS_SEEK:
    sys_seek ((int)arg0, (unsigned) arg1);
    break;

  case SYS_TELL:
    f->eax = (uint32_t) sys_tell ((int)arg0);
    break;

  case SYS_CLOSE:
    sys_close ((int)arg0);
    break;

  case SYS_FIBONACCI:
    f->eax = (uint32_t) sys_fibonacci ((int)arg0);
    break;

  case SYS_MAX_OF_FOUR_INT:
    f->eax = (uint32_t) sys_max_of_four_int ((int)arg0, (int)arg1, (int)arg2, (int)arg3);
    break;

  case SYS_MMAP:
    f->eax = (uint32_t) mmap ((int)arg0, (void *) arg1);
    break;

  case SYS_MUNMAP:
    munmap ((int)arg0);
    break;

  default:
    sys_exit (-1);
    break;
  }
}