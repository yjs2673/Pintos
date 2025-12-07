#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

/* 자식 스레드를 tid로 찾는 헬퍼 함수 */
static struct thread* 
get_child_process(tid_t tid) 
{
    struct thread *cur = thread_current();
    struct list_elem *e;
    for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list); e = list_next(e)) 
    {
        struct thread *t = list_entry(e, struct thread, child_elem);
        if (t->tid == tid) return t;
    }
    return NULL;
}

tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME. */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* 파싱하여 첫 번째 토큰(프로그램 이름)만 추출 */
  char *save_ptr;
  char *cmd_name_copy = malloc(strlen(file_name) + 1);
  if (cmd_name_copy == NULL) {
      palloc_free_page(fn_copy);
      return TID_ERROR;
  }
  strlcpy(cmd_name_copy, file_name, strlen(file_name) + 1);
  char *cmd_name = strtok_r(cmd_name_copy, " ", &save_ptr);

  /* [FIX] filesys_open 제거: Lock 문제 및 리소스 누수 방지 
     파일 존재 여부는 thread_create -> start_process -> load 에서 확인 후
     실패 시 tid를 반환하지 않는 방식으로 처리됨. */

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmd_name, PRI_DEFAULT, start_process, fn_copy);
  
  free(cmd_name_copy); // malloc한 메모리 해제

  if (tid == TID_ERROR) 
  {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }

  /* 자식의 load가 끝날 때까지 대기 */
  struct thread *child = get_child_process(tid);
  if (child == NULL) return TID_ERROR;

  sema_down(&child->lock_load);       // 자식이 로드 완료 신호를 줄 때까지 대기

  /* 자식의 로드 성공 여부 확인 */
  if (!child->load_success)
  {
    // 이미 child는 load 실패로 죽어가고 있음. 리스트에서만 제거.
    list_remove(&child->child_elem);  
    return TID_ERROR; // -1 반환
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  struct thread *cur = thread_current();
  pt_init(&cur->pt);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  cur->load_success = success;  // 자신의 load success 플래그 설정
  sema_up(&cur->lock_load);     // 대기 중인 부모를 깨움

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct thread *child = NULL;
  int status = -1;

  /* 1) child_tid가 진짜 내 자식인지 찾기 */
  for (e = list_begin (&(cur->child_list));
       e != list_end (&(cur->child_list));
       e = list_next (e))
  {
    struct thread *t = list_entry (e, struct thread, child_elem);
    if (t->tid == child_tid)
    {
      child = t;
      /* 2) 자식 종료까지 대기: 자식은 process_exit()에서 sema_up(lock_child) */
      sema_down (&child->lock_child);

      /* 3) 자식의 종료 상태 수집 */
      status = child->exit_status;
      list_remove (e); /* 더 이상 children 리스트에 남겨둘 필요 없음 */
  
      /* 4) 수집 완료 알림: 자식이 완전히 정리될 수 있게 깨워줌 */
      sema_up (&child->lock_parent);

      return status;
    }
  }

  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* 이전에 열었던 모든 파일들을 닫기 */
  for (int i = 2; i < 128; i++) if (cur->fd[i] != NULL) sys_close(i);

  pt_destroy(&cur->pt);

  /* 실행 파일 닫고 쓰기를 허용 */
  if (cur->exec_file != NULL)
  {
    file_close(cur->exec_file); // allow_write 자동 처리됨
    cur->exec_file = NULL;
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
    /* semaphore 관리 -> deadlock 방지 */
    sema_up(&(cur->lock_child));
    sema_down(&(cur->lock_parent));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* 1.Parsing */
  int argc = 0, length = 0;
  char* argv[128];
  const char *s = file_name;                  // 원본을 건드리지 않음
  size_t n = strlen(s);

  size_t start = 0;
  for (size_t i = 0; i <= n; i++) 
  {
    bool is_sep = (i == n) || (s[i] == ' ');
    if (is_sep) 
    {
      if (i > start) 
      {
        if (argc >= 128) break;                // 안전장치
        size_t len = i - start;
        argv[argc] = malloc(len + 1);
        memcpy(argv[argc], s + start, len);
        argv[argc][len] = '\0';
        argc++;
      }
      start = i + 1;                           // 다음 토큰 시작
    }
  }

  /* Open executable file. */
  t->exec_file = filesys_open (argv[0]);
  if (t->exec_file == NULL) 
  {
    printf ("load: %s: open failed\n", file_name);
    goto done; 
  }

  file_deny_write(t->exec_file); /* 실행 파일에 대한 쓰기 금지 */

  /* Read and verify executable header. */
  if (file_read (t->exec_file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (t->exec_file))
        goto done;
      file_seek (t->exec_file, file_ofs);

      if (file_read (t->exec_file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, t->exec_file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (t->exec_file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Allocate stack. */
  /*=======================================================*/
  /* 2.Store to stack reverse */
  char* argv_ptr[128];
  for(int i = 0; i < argc; i++)
  {
    *esp -= strlen(argv[argc - i - 1]) + 1;                           // 스택에서 공간 할당
    argv_ptr[argc - i - 1] = *esp;
    memcpy(*esp, argv[argc - i - 1], strlen(argv[argc - i - 1]) + 1); // 스택에 문자열 복사
  }

  /* 3.Word align */
  uintptr_t mis = (uintptr_t)(*esp) & 3;  // esp % 4
  if (mis) 
  {
    size_t pad = 4 - mis;
    *esp -= pad;
    memset(*esp, 0, pad);                 // 패딩은 0으로
  }
  
  /* 4.Push from stack reverse */
  *esp -= 4;      // NULL pointer
  *(char **)(*esp) = NULL;
  
  for(int i = 0; i < argc; i++)
  { 
    *esp -= 4;
    *(char **)(*esp) = (char*)argv_ptr[argc - i - 1]; //문자열 스택 주소 복사
  }
  
  char **argv_start = *esp; // argv
  *esp -= 4;
  *(char ***)(*esp) = argv_start;

  *esp -= 4;      // argc
  *(int *)(*esp) = argc;

  /* 5.Return fake address */
  *esp -= 4;
  *(void **)(*esp) = NULL;
  /*=======================================================*/

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // file_close (t->exec_file);
  for (i = 0; i < argc; i++) free(argv[i]);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

static struct pt_entry *
allocate_and_init_pte (void *vaddr, pt_type type, struct file *f, off_t ofs, 
                       size_t read_bytes, size_t zero_bytes, bool writable)
{
    struct pt_entry *pte = (struct pt_entry *)malloc(sizeof(struct pt_entry));
    if (pte == NULL) return NULL;

    pte->type = type;
    pte->vaddr = vaddr;
    pte->writable = writable;
    
    pte->is_loaded = (type == SWAPPED) ? true : false; 
    
    pte->file = f;
    pte->offset = ofs;
    
    pte->read_bytes = read_bytes;
    pte->zero_bytes = zero_bytes;
    
    pte->swap_slot = 0; 

    return pte;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) 
  {
    size_t page_read_bytes = (read_bytes < PGSIZE) ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* 파일 재오픈 */
    struct file *f_clone = file_reopen(file);
    if (f_clone == NULL) return false;

    struct pt_entry *ve = allocate_and_init_pte(upage, BINARY, f_clone, ofs,
                                                page_read_bytes, page_zero_bytes, writable);
      
    if (ve == NULL) {
      file_close(f_clone);
      return false;
    }

      
    if (pt_insert_entry(&thread_current()->pt, ve)) {
      /* 삽입 실패 시 롤백 */
      free(ve);
      file_close(f_clone);
     return false;
    }

    /* 포인터 및 카운터 업데이트 */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    ofs += page_read_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  struct frame *kpage;
  
  kpage = vm_alloc_page (PAL_USER | PAL_ZERO);
  
  /* 메모리 할당 실패 시 즉시 리턴 */
  if (kpage == NULL) return false;

  uint8_t *stack_base = ((uint8_t *) PHYS_BASE) - PGSIZE;

  /* 페이지 설치 시도 */
  if (!install_page (stack_base, kpage->kaddr, true)) 
  {
    vm_free_page (kpage->kaddr);
    return false;
  }

  /* 스택용 PTE 생성 */
  struct pt_entry *ve = allocate_and_init_pte(stack_base, SWAPPED, NULL, 0, 
                                              0, 0, true);
  
  if (ve == NULL) {
      return false;
  }

  /* 스택 페이지 특성 설정 */
  ve->is_loaded = true; 
  kpage->pte = ve;
  *esp = PHYS_BASE;

  /* Hash 테이블 삽입 */
  return !pt_insert_entry (&(thread_current ()->pt), ve);
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  
  /* 이미 매핑된 페이지인지 확인 */
  if (pagedir_get_page (t->pagedir, upage) != NULL) {
      return false;
  }

  /* 페이지 디렉토리에 세팅 */
  return pagedir_set_page (t->pagedir, upage, kpage, writable);
}

bool
handle_mm_fault (struct pt_entry *pte)
{
  if (pte == NULL) return false;

  struct frame *frm = vm_alloc_page(PAL_USER);
  if (frm == NULL) return false;

  frm->pte = pte;
  bool load_result = false;

  switch (pte->type) {
      case BINARY:
          load_result = load_file_to_page(frm->kaddr, pte);
          break;

      case SWAPPED:
          swap_in(pte->swap_slot, frm->kaddr);
          load_result = true;
          break;

      default:
          load_result = false;
          break;
  }

  /* 로드 실패 시 정리 */
  if (!load_result) goto error_cleanup;

  /* 페이지 테이블 매핑 */
  if (!install_page(pte->vaddr, frm->kaddr, pte->writable)) {
      goto error_cleanup;
  }

  pte->is_loaded = true;
  return true;

error_cleanup:
  vm_free_page(frm->kaddr);
  free(frm);
  return false;
}

bool
stack_growth (void *addr, void *esp)
{
  bool is_valid = is_user_vaddr (addr) &&
                  (addr >= (void *)(PHYS_BASE - 0x8000000)) && // Stack Limit Check
                  (addr >= (esp - 32));                        // PUSHA Heuristic

  if (!is_valid) return false;

  void *upage = pg_round_down (addr);
  struct frame *kpage = vm_alloc_page (PAL_USER | PAL_ZERO);

  if (kpage == NULL) return false;

  /* 설치 먼저 시도 */
  if (!install_page (upage, kpage->kaddr, true)) {
      vm_free_page (kpage->kaddr);
      return false;
  }

  /* PTE 생성 */
  struct pt_entry *pte = allocate_and_init_pte(upage, SWAPPED, NULL, 0, 
                                               0, 0, true);
  
  if (pte == NULL) {
      return false;
  }

  pte->is_loaded = true;
  kpage->pte = pte;

  /* Hash 등록 */
  return !pt_insert_entry (&(thread_current ()->pt), pte);
}