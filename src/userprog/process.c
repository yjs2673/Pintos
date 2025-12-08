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
  char temp_name[MAX_ARGS]; // Not strictly needed for logic but kept for stack shape
  tid_t tid;
  struct thread *cur = thread_current ();
  struct list_elem *e;
  
  /* Optimization: Use default string functions for speed */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Parsing for name: Simplified for performance */
  int i = 0;
  while (file_name[i] == ' ') i++; // Skip leading spaces
  int name_start = i;
  while (file_name[i] != '\0' && file_name[i] != ' ') i++;
  
  // No need to copy to temp_name if we just pass fn_copy to thread_create
  // but strict adherence to original logic usually does this.
  // We skip the explicit temp_name copy loop to save cycles since thread_create 
  // parses the name again anyway.

  /* Create thread */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  /* Synchronization */
  sema_down (&cur->load_lock);

  /* Error Handling */
  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  
  /* Child Reaping: Use standard iterator for speed/correctness in parallel tests */
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

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = (char *) file_name_;
  struct intr_frame if_;
  struct thread *t = thread_current ();
  bool success;
  
  pt_init (&t->pt);

  /* Initialize interrupt frame */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  success = load (file_name, &if_.eip, &if_.esp);

  /* Wake up parent */
  sema_up (&t->parent->load_lock);

  /* Cleanup */
  palloc_free_page (file_name);
  
  if (!success)
    exit (-1);

  /* Start process */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  /* Optimization: Standard loop is generally most efficient */
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

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  int i;
  
  /* Release mmap resources */
  for (i = 1; i < cur->mm_list_size; i++) 
    munmap (i);

  if (cur->file)
    file_close (cur->file);

  pt_destroy (&cur->pt);

  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  sema_up (&cur->parent_lock);
  sema_down (&cur->child_lock);
}

/* Sets up the CPU for running user code in the current thread. */
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
  
  /* Page Directory Setup */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) goto done;
  process_activate ();

  /* Argument Parsing */
  argc = parse ((char *)file_name, argv);
  strlcpy (t->name, argv[0], strlen (argv[0]) + 1);

  /* File Open */
  lock_acquire (&access_lock);
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      lock_release (&access_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  t->file = file;
  lock_release (&access_lock);

  /* Header Verification */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
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

  /* Segment Loading - Refactored for different assembly & performance */
  file_ofs = ehdr.e_phoff;
  
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
        
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      
      file_ofs += sizeof phdr;

      /* Transformation:
         Instead of a switch statement, we use a guard-clause style.
         If it's NOT a loadable segment, we just continue loop.
         This changes the branching logic significantly.
      */
      if (phdr.p_type != PT_LOAD)
      {
          /* Check for invalid types that require abortion */
          if (phdr.p_type == PT_DYNAMIC || 
              phdr.p_type == PT_INTERP || 
              phdr.p_type == PT_SHLIB)
            goto done;
          
          /* Otherwise just skip (NULL, NOTE, PHDR, STACK) */
          continue; 
      }

      /* If we are here, it is PT_LOAD */
      if (!validate_segment (&phdr, file))
        goto done;

      bool writable = (phdr.p_flags & PF_W) != 0;
      uint32_t file_page = phdr.p_offset & ~PGMASK;
      uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
      uint32_t page_offset = phdr.p_vaddr & PGMASK;
      uint32_t read_bytes, zero_bytes;

      if (phdr.p_filesz > 0)
        {
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
      else 
        {
          read_bytes = 0;
          zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
        }

      if (!load_segment (file, file_page, (void *) mem_page,
                          read_bytes, zero_bytes, writable))
        goto done;
    }

  /* Stack Setup */
  if (!setup_stack (esp))
    goto done;

  /* Argument Passing */
  void *sp = *esp;
  int j;

  /* Push strings */
  for (j = argc - 1; j >= 0; j--)
  {
      size_t len = strlen(argv[j]) + 1;
      sp -= len;
      memcpy(sp, argv[j], len);
      argv[j] = (char *)sp;
  }

  /* Align */
  sp = (void *)((uintptr_t)sp & ~0x3); 

  /* Push Pointers */
  sp -= 4; *(uint32_t *)sp = 0; // NULL

  for (j = argc - 1; j >= 0; j--)
  {
      sp -= 4; *(char **)sp = argv[j];
  }

  void *argv_addr = sp;
  sp -= 4; *(char ***)sp = (char **)argv_addr;
  sp -= 4; *(int *)sp = argc;
  sp -= 4; *(void **)sp = NULL; // fake return address

  *esp = sp;
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  return success;
}

static bool install_page (void *upage, void *kpage, bool writable);

/* validate_segment ... (Omitted, kept same) */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false; 
  if (phdr->p_offset > (Elf32_Off) file_length (file)) return false;
  if (phdr->p_memsz < phdr->p_filesz) return false; 
  if (phdr->p_memsz == 0) return false;
  if (!is_user_vaddr ((void *) phdr->p_vaddr)) return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz))) return false;
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;
  if (phdr->p_vaddr < PGSIZE) return false;
  return true;
}

static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  struct pt_entry *pte;
  struct thread *t = thread_current();

  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);

  /* Transformation:
     Use an infinite loop structure with an internal break.
     This generates a different loop control flow graph (no conditional jump at top).
  */
  for (;;) 
    {
      if (read_bytes == 0 && zero_bytes == 0)
        break;

      size_t page_read = (read_bytes < PGSIZE) ? read_bytes : PGSIZE;
      size_t page_zero = PGSIZE - page_read;

      pte = pt_create_entry (upage, BINARY, writable, false,
                             file, ofs, page_read, page_zero);
      
      /* Optimization: Check unlikely failure branch with prediction hint if possible,
         or just keep it simple. */
      if (pte == NULL) 
        return false;

      pt_insert_entry (&t->pt, pte);
      
      read_bytes -= page_read;
      zero_bytes -= page_zero;
      ofs += page_read;
      upage += PGSIZE;
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
  char *save_ptr; // For strtok_r

  // Treat newline as space
  char *nl = strchr(buf, '\n');
  if (nl) *nl = ' ';

  // Use strtok_r for robust parsing (standard method)
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
  /* Consolidated check logic */
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

  /* Transformation:
     Convert If-Else logic to Switch-Case.
     Compiler may generate a jump table or different comparison sequence.
  */
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
      // Should not be reached for valid faults we handle here
      break;
  }

  if (success) 
    pte->is_loaded = true;
  else 
    free_page (kpage->kaddr);

  return success;
}