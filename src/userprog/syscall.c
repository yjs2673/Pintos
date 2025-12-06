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
#include <string.h>
#include <stdlib.h>

typedef int pid_t;

void shutdown_power_off (void);             /* devices/shutdown.h */
uint8_t input_getc (void);                  /* devices/input.h */
void putbuf (const char *buffer, size_t n); /* lib/kernel/console.h */

static void syscall_handler (struct intr_frame *);

/* Filesystem serialization lock */
// static struct lock filesys_lock;

/* uaddr가 유저 영역에 매핑되어 있는지 확인 */
static void
validate_ptr (const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr (uaddr) ||
      pagedir_get_page (thread_current ()->pagedir, uaddr) == NULL)
    {
      sys_exit (-1);
    }
}

/* 유저 메모리에서 32비트 값을 안전히 읽기 */
static int32_t
get_user_int (const void *uaddr)
{
  validate_ptr (uaddr);
  // validate_ptr (uaddr + 3); /* 4바이트 패딩 */
  return *(const int32_t *) uaddr;
}

/* size 바이트 범위를 모두 확인 */
/* 쓰기 가능한 버퍼 검증 */
static void
validate_writable_buffer (void *buf, unsigned size)
{
  for (unsigned i = 0; i < size; i++)
    validate_ptr ((uint8_t *) buf + i);
}

/* 읽기 전용 버퍼 검증. */
static void
validate_readable_buffer (const void *buf, unsigned size)
{
  for (unsigned i = 0; i < size; i++)
    validate_ptr ((const uint8_t *) buf + i);
}

/* NUL로 끝나는 문자열 전체를 검증. */
static void
validate_cstr (const char *str)
{
  validate_ptr (str);
  while (*str != '\0')
    {
      validate_ptr (str);
      str++;
    }
}

/* syscall function */
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

/* User Program 2 */
bool sys_create (const char *file, unsigned initial_size)
{
  if (file == NULL) sys_exit(-1);
  validate_cstr(file);
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool sys_remove (const char *file)
{
  if (file == NULL) sys_exit(-1);
  validate_cstr(file);
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int sys_open (const char *file)
{
  if (file == NULL) sys_exit(-1);
  validate_cstr(file);
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (f == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }

  struct thread *t = thread_current();
  // Find an empty spot in the file descriptor table (start from 2, as 0 and 1 are reserved)
  for (int i = 2; i < 128; i++)
  {
    if (t->fd[i] == NULL)
    {
      t->fd[i] = f;
      lock_release(&filesys_lock);
      return i;
    }
  }

  // No available file descriptor
  file_close(f);
  lock_release(&filesys_lock);
  return -1;
}

int sys_filesize (int fd)
{
  if (fd < 2 || fd >= 128) return -1;
  
  struct thread *t = thread_current();
  struct file *f = t->fd[fd];

  if (f == NULL) return -1;

  lock_acquire(&filesys_lock);
  int size = file_length(f);
  lock_release(&filesys_lock);
  return size;
}

int sys_read (int fd, void *buffer, unsigned size)
{
  /* 1. 버퍼 주소 유효성 검사 (아직 쓰기 권한 체크는 안함) */
  if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size)) return -1;
  if (fd == 1) return -1; // STDOUT 읽기 불가

  /* 2. STDIN 처리 */
  if (fd == 0) {
      /* 키보드 입력은 락 불필요하거나, 필요하다면 여기서만 잡음 */
      uint8_t *buf = (uint8_t *)buffer;
      for (unsigned i = 0; i < size; i++) buf[i] = input_getc();
      return size;
  }

  /* 3. 파일 처리 */
  struct thread *t = thread_current();
  if (fd < 2 || fd >= 128) return -1;
  struct file *f = t->fd[fd];
  if (f == NULL) return -1;

  /* [핵심] 커널 버퍼 할당 */
  void *kbuffer = malloc(size);
  if (kbuffer == NULL) return -1;

  /* [핵심] 락 잡고 -> 커널 버퍼에 읽기 -> 락 해제 */
  lock_acquire(&filesys_lock);
  int bytes_read = file_read(f, kbuffer, size);
  lock_release(&filesys_lock);

  /* [핵심] 유저 버퍼로 복사 (여기서 Page Fault 나도 락 없음 -> OK) */
  memcpy(buffer, kbuffer, bytes_read);
  free(kbuffer);

  return bytes_read;
}

/* [수정됨] Write 구현 */
int sys_write (int fd, const void *buffer, unsigned size)
{
  if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size)) return -1;
  if (fd == 0) return -1; // STDIN 쓰기 불가

  /* STDOUT 처리 */
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }

  struct thread *t = thread_current();
  if (fd < 2 || fd >= 128) return -1;
  struct file *f = t->fd[fd];
  if (f == NULL) return -1;

  void *kbuffer = malloc(size);
  if (kbuffer == NULL) return -1;
  memcpy(kbuffer, buffer, size);

  lock_acquire(&filesys_lock);
  int bytes_written = file_write(f, kbuffer, size);
  lock_release(&filesys_lock);

  free(kbuffer);
  return bytes_written;
}

/* [수정됨] Exec 구현 */
pid_t sys_exec (const char *cmd_line)
{
  if (!is_user_vaddr(cmd_line)) return -1;
  
  /* 락 생략, process_execute가 처리 */
  return process_execute (cmd_line);
}
void sys_seek (int fd, unsigned position)
{
  if (fd < 2 || fd >= 128) return;
  
  struct thread *t = thread_current();
  struct file *f = t->fd[fd];

  if (f == NULL) return;

  lock_acquire(&filesys_lock);
  file_seek(f, position);
  lock_release(&filesys_lock);
}

unsigned sys_tell (int fd)
{
  if (fd < 2 || fd >= 128) return 0;

  struct thread *t = thread_current();
  struct file *f = t->fd[fd];

  if (f == NULL) return 0;

  lock_acquire(&filesys_lock);
  unsigned position = file_tell(f);
  lock_release(&filesys_lock);
  return position;
}

void sys_close(int fd) {
    if (fd < 2 || fd >= 128) return;
    struct thread *t = thread_current();
    if (t->fd[fd] == NULL) return;
    
    lock_acquire(&filesys_lock);
    file_close(t->fd[fd]);
    t->fd[fd] = NULL;
    lock_release(&filesys_lock);
}
/*================*/

int sys_fibonacci (int n)
{
  if (n < 0 || n > 46) return -1;   /* 범위 밖은 예외처리 */

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
  lock_init (&filesys_lock); /* 파일 시스템 lock init */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = f->esp;

  validate_ptr (esp);
  int sysno = get_user_int (esp);

  int32_t arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0;
  if (sysno == SYS_HALT || sysno == SYS_EXIT || sysno == SYS_EXEC || 
      sysno == SYS_WAIT || sysno == SYS_CREATE || sysno == SYS_REMOVE ||
      sysno == SYS_OPEN || sysno == SYS_FILESIZE || sysno == SYS_SEEK ||
      sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_TELL ||
      sysno == SYS_CLOSE || sysno == SYS_FIBONACCI || sysno == SYS_MAX_OF_FOUR_INT)
  {
    if (sysno != SYS_HALT)                
      arg0 = get_user_int ((uint8_t *) esp + 4);  // 1 arg
    if (sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_MAX_OF_FOUR_INT ||
        sysno == SYS_CREATE || sysno == SYS_SEEK)
      arg1 = get_user_int ((uint8_t *) esp + 8);  // 2 arg
    if (sysno == SYS_READ || sysno == SYS_WRITE || sysno == SYS_MAX_OF_FOUR_INT)  
      arg2 = get_user_int ((uint8_t *) esp + 12); // 3 arg
    if (sysno == SYS_MAX_OF_FOUR_INT)             
      arg3 = get_user_int ((uint8_t *) esp + 16); // 4 arg
  }

  switch (sysno)
  {
  case SYS_HALT:
    sys_halt ();
    break;

  case SYS_EXIT:
    sys_exit (arg0);
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
    f->eax = (uint32_t) sys_filesize (arg0);
    break;

  case SYS_READ:
    f->eax = (uint32_t) sys_read (arg0, (void *) arg1, (unsigned) arg2);
    break;

  case SYS_WRITE:
    f->eax = (uint32_t) sys_write (arg0, (const void *) arg1, (unsigned) arg2);
    break;

  case SYS_SEEK:
    sys_seek (arg0, (unsigned) arg1);
    break;

  case SYS_TELL:
    f->eax = (uint32_t) sys_tell (arg0);
    break;

  case SYS_CLOSE:
    sys_close (arg0);
    break;

  case SYS_FIBONACCI:
    f->eax = (uint32_t) sys_fibonacci (arg0);
    break;

  case SYS_MAX_OF_FOUR_INT:
    f->eax = (uint32_t) sys_max_of_four_int (arg0, arg1, arg2, arg3);
    break;

  default:
    sys_exit (-1);
    break;
  }
}