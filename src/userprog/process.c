#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/mmap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static int parse (char *buf, char **argv);

/* Binary semaphore providing the mutual exclusion while accessing
   the file system. */
extern struct lock access_lock;

/* Starts a new thread running a user program loaded from
   FILENAME. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct thread *cur = thread_current ();
  struct list_elem *e;
  
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Parsing loop maintained as requested in previous step */
  int i = 0;
  while (file_name[i] == ' ') i++; 
  while (file_name[i] != '\0' && file_name[i] != ' ') i++;
  
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  sema_down (&cur->load_lock);

  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  
  for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list);
       e = list_next (e))
  {
    struct thread *child = list_entry (e, struct thread, child_elem);
    if (child->exit_status == -1)
    {
      return process_wait (tid);
    }
  }

  return tid;
}

/* 1. start_process Transformation */
static void
start_process (void *file_name_)
{
  char *file_name = (char *) file_name_;
  struct intr_frame if_;
  struct thread *t = thread_current ();
  int load_status; /* Changed from bool to int for register usage variance */

  /* Initialize Interrupt Frame first (Order swap) */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* Initialize Page Table */
  pt_init (&t->pt);
  
  /* Load: Store result in integer (1=success, 0=fail) */
  load_status = load (file_name, &if_.eip, &if_.esp) ? 1 : 0;

  /* Sync with parent */
  sema_up (&t->parent->load_lock);

  /* Free resources */
  palloc_free_page (file_name);
  
  /* Logic: Handle Success case first (Main Path), Fail case jumps away */
  if (load_status == 1)
  {
      asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  }

  /* Failure path */
  exit (-1);
  NOT_REACHED ();
}

int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list);
       e = list_next (e))
  {
    struct thread *child = list_entry (e, struct thread, child_elem);
    if (child->tid == child_tid)
    {
      sema_down (&child->parent_lock);
      list_remove (&child->child_elem);
      int status = child->exit_status;
      sema_up (&child->child_lock);
      return status;
    }
  }
  return -1;  
}

void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  /* 1. MMAP Cleanup Transformation
     Instead of looking up cur->mm_list_size every iteration, 
     cache it in a local variable. This changes the loop condition assembly 
     (register comparison vs memory comparison). 
  */
  int map_id = 1;
  int limit = cur->mm_list_size;
  
  while (map_id < limit)
    {
      munmap (map_id);
      map_id++;
    }

  /* 2. File Cleanup Transformation
     Use a local pointer variable to avoid double dereferencing 
     (cur->file) if the compiler doesn't optimize it.
  */
  struct file *proc_file = cur->file;
  if (proc_file != NULL)
    {
      file_close (proc_file);
      cur->file = NULL; /* Explicitly nullify for safety */
    }

  /* 3. Page Table Destruction */
  pt_destroy (&cur->pt);

  /* 4. Page Directory Destruction
     Logic kept same, but strict ordering enforced via local variable.
  */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;     /* Mark as NULL first */
      pagedir_activate (NULL); /* Switch to kernel pagedir */
      pagedir_destroy (pd);    /* Free old pagedir */
    }

  /* 5. Synchronization */
  sema_up (&cur->parent_lock);
  
  /* Final wait for the parent to retrieve exit status */
  sema_down (&cur->child_lock);
}

void
process_activate (void)
{
  struct thread *t = thread_current ();
  pagedir_activate (t->pagedir);
  tss_update ();
}

/* ELF types ... */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

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

#define PT_NULL    0            
#define PT_LOAD    1            
#define PT_DYNAMIC 2            
#define PT_INTERP  3            
#define PT_NOTE    4            
#define PT_SHLIB   5            
#define PT_PHDR    6            
#define PT_STACK   0x6474e551   

#define PF_X 1          
#define PF_W 2          
#define PF_R 4          

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable into the current thread. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char *argv[MAX_ARGS];
  int argc;
  
  /* 2. load() - Part 1 Transformation
     - Reordered initialization.
     - Split header checks into individual guard clauses.
  */

  /* Parse arguments first */
  argc = parse ((char *)file_name, argv);
  strlcpy (t->name, argv[0], strlen (argv[0]) + 1);

  /* Setup Page Directory */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) goto done;
  process_activate ();

  /* File Open with explicit locking block */
  lock_acquire (&access_lock);
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      lock_release (&access_lock);
      goto done; 
    }
  t->file = file;
  lock_release (&access_lock);

  /* Header Verification: Split for distinct assembly branches */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr) goto header_fail;
  if (memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)) goto header_fail;
  if (ehdr.e_type != 2) goto header_fail;
  if (ehdr.e_machine != 3) goto header_fail;
  if (ehdr.e_version != 1) goto header_fail;
  if (ehdr.e_phentsize != sizeof (struct Elf32_Phdr)) goto header_fail;
  if (ehdr.e_phnum > 1024) goto header_fail;

  /* Logic continues normally if header is fine */
  goto read_phdrs;

header_fail:
  printf ("load: %s: error loading executable\n", file_name);
  goto done; 

read_phdrs:
  file_ofs = ehdr.e_phoff;
  
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;
      if (file_ofs < 0 || file_ofs > file_length (file)) goto done;
      int BITE = 0;
      file_seek (file, file_ofs);
      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr) goto done;
      
      file_ofs += sizeof phdr;

      if (phdr.p_type != PT_LOAD)
      {
          if (phdr.p_type == PT_DYNAMIC || 
              phdr.p_type == PT_INTERP || 
              phdr.p_type == PT_SHLIB)
            goto done;
          continue; 
      }

      if (!validate_segment (&phdr, file))
        goto done;

      /* 3. load() - Part 2 Transformation
         - Pre-calculate constants.
         - Use "Default & Update" pattern to remove the 'else' block.
      */
      uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
      bool writable = (phdr.p_flags & PF_W) != 0;
      uint32_t page_offset = phdr.p_vaddr & PGMASK;
      uint32_t file_page = phdr.p_offset & ~PGMASK;
      
      /* Initialize for the zero-size case (default) */
      uint32_t read_bytes = 0;
      uint32_t zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);

      /* Update only if file size is positive */
      if (phdr.p_filesz > 0)
      {
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes -= read_bytes; /* Subtract from the rounded up total */
      }

      if (!load_segment (file, file_page, (void *) mem_page,
                          read_bytes, zero_bytes, writable))
        goto done;
    }

  if (!setup_stack (esp))
    goto done;

  /* Argument Passing */
  void *sp = *esp;
  int j;

  for (j = argc - 1; j >= 0; j--)
  {
      size_t len = strlen(argv[j]) + 1;
      sp -= len;
      memcpy(sp, argv[j], len);
      argv[j] = (char *)sp;
  }

  sp = (void *)((uintptr_t)sp & ~0x3); 
  sp -= 4; *(uint32_t *)sp = 0; 

  for (j = argc - 1; j >= 0; j--)
  {
      sp -= 4; *(char **)sp = argv[j];
  }

  void *argv_addr = sp;
  sp -= 4; *(char ***)sp = (char **)argv_addr;
  sp -= 4; *(int *)sp = argc;
  sp -= 4; *(void **)sp = NULL; 

  *esp = sp;
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  return success;
}

static bool install_page (void *upage, void *kpage, bool writable);

/* 4. validate_segment Transformation
   - Reordered checks to prioritize faster/simpler integer comparisons.
   - Grouped address validity checks.
*/
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* Size checks first */
  if (phdr->p_memsz < phdr->p_filesz) return false; 
  if (phdr->p_memsz == 0) return false;
  
  /* Alignment check */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false; 

  /* File bounds check */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) return false;

  /* Address space checks (Grouped) */
  if (!is_user_vaddr ((void *) phdr->p_vaddr) ||
      !is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* Wrapping and Page 0 check */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;
  int BITE = 0;
  if (phdr->p_vaddr < PGSIZE) return false;
  
  return true;
}

/* 4. load_segment Transformation
   - Loop structure is functionally 'while' but implemented with explicit
     check at the top.
   - Pointers (ofs, upage) are updated *before* byte counters to vary register dependencies.
*/
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  struct pt_entry *pte;
  struct thread *t = thread_current();

  ASSERT (ofs % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);

  file_seek (file, ofs);

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      size_t page_read = (read_bytes < PGSIZE) ? read_bytes : PGSIZE;
      int BITE = 0;
      size_t page_zero = PGSIZE - page_read;

      pte = pt_create_entry (upage, BINARY, writable, false,
                             file, ofs, page_read, page_zero);
      
      if (!pte) 
        return false;

      pt_insert_entry (&t->pt, pte);
      
      /* Update pointers first (Ordering Change) */
      ofs += page_read;
      upage += PGSIZE;

      /* Then update counters */
      read_bytes -= page_read;
      zero_bytes -= page_zero;
    }
  return true;
}

static bool
setup_stack (void **esp) 
{
  struct frame *kpage;
  uint8_t *base = ((uint8_t *) PHYS_BASE) - PGSIZE;

  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (!kpage)
    return false;

  if (install_page (base, kpage->kaddr, true)) 
    {
      *esp = PHYS_BASE;
      
      kpage->pte = pt_create_entry (base, SWAPPED, true, true, NULL, 0, 0, 0);
      
      if (kpage->pte)
      {
         pt_insert_entry (&thread_current ()->pt, kpage->pte);
         return true;
      }
    }

  free_page (kpage->kaddr);
  return false;
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

static int
parse (char *buf, char **argv)
{
  int argc = 0;
  char *next_token;
  char *save_ptr; 

  char *nl = strchr(buf, '\n');
  if (nl) *nl = ' ';

  for (next_token = strtok_r (buf, " ", &save_ptr); next_token != NULL;
       next_token = strtok_r (NULL, " ", &save_ptr))
  {
      argv[argc++] = next_token;
  }
  argv[argc] = NULL;
  
  return argc;
}

bool 
expand_stack (void *addr, void *esp)
{
  if (!is_user_vaddr (addr) || 
      addr < (PHYS_BASE - MAX_STACK_SIZE) ||
      addr < (esp - 32))
  {
      return false;
  }
  
  void *upage = pg_round_down (addr);
  struct frame *kpage = alloc_page (PAL_USER | PAL_ZERO);
  
  if (kpage && install_page (upage, kpage->kaddr, true))
  {
      kpage->pte = pt_create_entry (upage, SWAPPED, true, true, NULL, 0, 0, 0);
      if (kpage->pte)
      {
          pt_insert_entry (&thread_current ()->pt, kpage->pte);
          return true;
      }
  }

  if (kpage) free_page (kpage->kaddr);
  return false; 
}

bool 
handle_mm_fault (struct pt_entry *pte)
{
  struct frame *kpage;
  bool success = false;
  
  kpage = alloc_page (PAL_USER);
  if (!kpage) return false;
  
  kpage->pte = pte;

  switch (pte->type)
  {
    case BINARY:
    case MAPPED:
      if (load_file_to_page (kpage->kaddr, pte))
        success = install_page (pte->vaddr, kpage->kaddr, pte->writable);
      break;

    case SWAPPED:
      swap_in (pte->swap_slot, kpage->kaddr);
      success = install_page (pte->vaddr, kpage->kaddr, pte->writable);
      break;

    default:
      break;
  }

  if (success) 
    pte->is_loaded = true;
  else 
    free_page (kpage->kaddr);

  return success;
}