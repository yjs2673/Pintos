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
   the file system. (declared in 'userprog/syscall.h' file) */
extern struct lock access_lock;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  struct list *c_list;
  struct list_elem* iter; struct thread *entry;
  int cmd_len = strlen (file_name) + 1, i, idx = 0;
  char temp_name[MAX_ARGS];
  char *fn_copy;
  tid_t tid;
  
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Check whether there exists a file named 'file_name' in file system 
     It handles the execution-with-missing-arguments situation. */
  for (i = 0; file_name[i] == ' '; i++);
  for (; i < cmd_len; i++) 
    {
      if (file_name[i] == ' ' || 
          file_name[i] == '\0') break;
      temp_name[idx++] = file_name[i];
    }
  temp_name[idx] = '\0';

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  /* Prevent the situation that the running process abno-
     -rmally finishes 'exec' earlier than the load routine. */
  sema_down (&(thread_current ()->load_lock));

  /* If an error occured in the loading phase, then free 
     the allocated page of that newly created thread. */
  if (tid == TID_ERROR)
     palloc_free_page (fn_copy);
  
  /* Reap every child that exited abnormally while 
     loading or while start_process routine. */
  c_list = &(thread_current ()->child_list);
  for (iter = list_begin (c_list); 
      iter != list_end (c_list); 
      iter = list_next (iter))
    {
      entry = list_entry(iter, struct thread, child_elem);
      if (entry->exit_status == -1)                               
        return process_wait (tid);
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
  
  /* Initialize the page table of newly created process. */
  pt_init (&(thread_current ()->pt));

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* After the load routine ends successfully, wake
     up the parent process of current(child) process. */
  sema_up (&((thread_current ()->parent)->load_lock));

  /* If load failed, quit and exit with status -1.
     Reaping will be made in the process_execute routine */
  palloc_free_page (file_name);
  if (!success)
    exit (-1);

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
  struct list *c_list = &(thread_current ()->child_list);
  struct list_elem *iter; struct thread *entry;

  for (iter = list_begin (c_list);
      iter != list_end (c_list);
      iter = list_next (iter))
    {
      entry = list_entry(iter, struct thread, child_elem);
      if (entry->tid == child_tid)
        {
          /* Make current(parent) process go to sleep. */
          sema_down (&(entry->parent_lock));
          
          /* If parent wakes up and child goes to sleep, then 
             remove the list entry of current child. */
          list_remove (&(entry->child_elem));

          /* Tell the child process to wake up! */
          sema_up (&(entry->child_lock));

          return (entry->exit_status);
        }
    }

  return -1;  
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd; unsigned i;
  
  /* If there're mmapped pages that are not freed yet,
     dellocate all of it, by calling munmap syscall. */
  for (i = 1; i < cur->mm_list_size; i++) munmap (i);

  /* Close the mapped file of this(current) thread. */
  file_close (cur->file);

  /* Deallocate the page table. */
  pt_destroy (&(cur->pt));

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

  /* When a current(child) process exits, make
     the sleeping parent process wake up! */
  sema_up (&(cur->parent_lock));

  /* And the current(child) process immediately
     and shortly sleeps for the list pop operation. */
  sema_down (&(cur->child_lock));
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
  struct Elf32_Ehdr ehdr; struct thread *t = thread_current ();
  struct file *file = NULL; off_t file_ofs; 
  char *fn_ptr = file_name; char *argv[MAX_ARGS];
  size_t total_len, temp_len; int argc, i;
  bool success = false;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Parse the entire command line into argument tokens. */
  argc = parse (fn_ptr, argv);
  strlcpy(thread_name (), argv[0], strlen (argv[0]) + 1);

  /* Open and map an executable file. Note that this file system access must 
     be protected by mutex lock. We should keep in mind that a synchronization
     is the most important thing in the lazy loading implementation. */
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

  /* Read and verify executable header. */
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

  /* Read program headers. */
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
          if (validate_segment (&phdr, file)) 
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
              if (!load_segment (file, file_page, (void *) mem_page,
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

/* Macros for raising a readability */
#define S_EXPAND(amount) *esp = (uint8_t*)(*esp) - amount
// S_EXPAND: Expand stack downward, by using subtraction of pointers
#define S_SETVAL(value) *(uint32_t*)(*esp) = value
// S_SETVAL: Set the value of argument on the address pointed by esp

  /* Push(pass) arguments into stack, by modifying esp pointer. */
  total_len = 0;
  for (i = argc - 1; i >= 0; i--) 
    {
      temp_len = (strlen (argv[i]) + 1);
      total_len += temp_len;

      S_EXPAND(temp_len);
      memcpy (*esp, argv[i], temp_len);
      argv[i] = *esp;
    }

  /* Word Alignment for 80x86 */
  temp_len = 4 - (total_len % 4);
  if (temp_len != 4) 
    {
      while (temp_len--) 
        {
          S_EXPAND(1);
          memset (*esp, 0, 1);
        }
    }

  for (i = argc; i >= 0; i--)
    {
      S_EXPAND(4);
      if (i == argc) S_SETVAL(0);
      else S_SETVAL((uint32_t)argv[i]);
    }
  S_EXPAND(4); /**/ S_SETVAL((uint32_t)((uint8_t*)(*esp) + 4)); // argv addr
  S_EXPAND(4); /**/ S_SETVAL(argc);                             // argc
  S_EXPAND(4); /**/ S_SETVAL(0);                                // ret addr
  // hex_dump((uintptr_t)*esp, *esp, PHYS_BASE - (uintptr_t)*esp, true);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
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

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. 
   
   In the project 4 phase, the lazy loading concept has been applied 
   to here, and you can see the differences right below codes. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  struct pt_entry *pte;

  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Create a page table entry for this, and push to the 
         page table. Note that this is not a loading, this is
         just constructing the page table only. (Lazy Loading) */
      pte = pt_create_entry (upage, BINARY, writable, false,
        file, ofs, page_read_bytes, page_zero_bytes);
      if(pte == NULL) return false;

      pt_insert_entry (&(thread_current ()->pt), pte);
      
      /* Advance. Note that the offset is updated. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. 
   In the project 4 phase, the lazy loading concept has been applied 
   to here, and you can see the differences right below codes. */
static bool
setup_stack (void **esp) 
{
  struct frame *kpage;
  bool success = false;

  /* We should note that the function 'alloc_page' below provides a frame 
     allocation based on the lazy loading concepts. You can see more details 
     about it in 'vm/frame.h' file, and in here, it's enough to know that
     this function returns a newly created page-sized frame. */
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      /* Record this new frame to the 'read(non-supplemental)' page table.
         And then, set the esp pointer value as recommended. */
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      if (success) 
        {
          *esp = PHYS_BASE;

          /* After installing pages for the stack segment, then 
             create a page table entry for these pages and push 
             it to the supplemental page table of current thread. */
          kpage->pte = pt_create_entry (((uint8_t *)PHYS_BASE) - PGSIZE, 
            SWAPPED, true, true, NULL, 0, 0, 0);
          if (kpage->pte == NULL) return false;

          pt_insert_entry (&(thread_current ()->pt), kpage->pte);
        }
      else
        free_page (kpage->kaddr);
    }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Function that parses input string, and makes an array
   consists of tokens. */
static int
parse (char *buf, char **argv)
{
  char *delim; int argc;

  if (buf[strlen (buf) - 1] == '\n')
    buf[strlen (buf) - 1] = ' ';
  else buf[strlen (buf)] = ' ';

  while (*buf && (*buf == ' '))
    buf++;

  argc = 0;
  while ((delim = strchr (buf, ' ')))
    {
      argv[argc++] = buf;
      *delim = '\0';

      buf = delim + 1;
      while (*buf && (*buf == ' '))
        buf++;
    }
  argv[argc] = NULL;

  return argc;
}


/* Functions below are procedures for page fault handling. */

/* When a memory reference encounters an error and thus invokes the 
   'page_fault()' in exception.c, there're three actions that could
   occur. 
     - The first one is a segmentation/protection fault which means 
       just a termination (not present). 
     - And the second one is a page fault situation which means the
       memory reference is valid (Look at the 'handle_mm_fault' func). 
     - The last one is this. Present but not valid reference, that
       needs a stack growth (This fuction does this). 
   The manual says the maximum expansion is up to 8MB of stack. 
    
   Meanwhile, every time the user thread try to use system calls, if
   a memory access request from the user needs stack expansion, this
   function gonna be called to perform the expected action. */
bool 
expand_stack (void *addr, void *esp)
{
  void *upage;
  struct frame *kpage;
  bool success = false;
  
  /* Is it OK to expand the stack in this case? That is, check if the 
     faulting address can be within the 8MB range from the current stack 
     pointer address, and whether it's from the user-virtual area, and 
     qualify the PUSHA condition also. All these 3 checks should be passed. */
  if (!is_user_vaddr (addr)) return false;
  if (addr < (PHYS_BASE - MAX_STACK_SIZE)) return false;
  if (addr < (esp - 32)) return false;
  
  /* Get the nearest page boudary, to 'upage'. */
  upage = pg_round_down (addr);

  /* If the previous checking was successful, then expand 
     the stack just like the way we set up the stack, except
     for the setting routine of the esp pointer. */
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (upage, kpage->kaddr, true);
      if (success)
        {
          kpage->pte = pt_create_entry (upage, SWAPPED, true, true,
            NULL, 0, 0, 0);
          if (kpage->pte == NULL) return false;

          pt_insert_entry (&(thread_current ()->pt), kpage->pte);
        }
      else
        free_page (kpage->kaddr);
    }

  return success; 
}

/* This is the main part of the page fault handling procedures.
   (See the previous description in the comment of 'stack-growth routine')

   'page_fault()' function in exception.c calls this function if the
   faulting address is from the valid reference, which means the type
   of the fault is not a segmentation or protection fault. 
   
   Meanwhile, in case you are curious about that why this 'page fault 
   handling' routine is declared in 'process.h' not in 'exception.h',
   I brought the reason, that is, it's because of 'install_page' func. 
   The basic pintOS system want 'install_page' func remains as static,
   so I choose to declare this function here. Not a big reason. */
bool 
handle_mm_fault (struct pt_entry *pte)
{
  struct frame *kpage;
  bool success = false;

  /* Allocate a new physical frame and map to the passed PTE.
     This frame possibly replaces the original virtual page.*/
  kpage = alloc_page (PAL_USER);
  kpage->pte = pte;

  /* What is a type of the virtual page of the faulting address?
      --> here are two cases by type of page, just like below. 
     (1) If it's the binary file or the mmapped file, then simply
       load related data from the same file in the disk-side.*/
  if (pte->type == BINARY || pte->type == MAPPED)
    {
      if (load_file_to_page (kpage->kaddr, pte))
        success = install_page (pte->vaddr, kpage->kaddr, pte->writable);
    }

  /* (2) If it's the page that are from the swap space but not in
       the memory right now, just swapping in that frame. Note that in 
       both cases we just install the newly created frame into system. */
  else if (pte->type == SWAPPED)
    { 
      swap_in (pte->swap_slot, kpage->kaddr);
      success = install_page (pte->vaddr, kpage->kaddr, pte->writable);
    }

  /* If installation(frame-to-page mapping in 'real' 
     page table) is done, then set this page as 'loaded'. 
     If installation failed, then free that newly created frame. */
  if (success) 
    pte->is_loaded = true;
  else 
    free_page (kpage->kaddr);

  return success;
  /* If it reaches here with success == true, then the loading is successful.
     Thus, 'page_fault()' will return properly, and the system will execute
     the faulting instruction once again. (fault exception handling) */
}
