#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

/* This header file is the core of the project 4 phase, that is, the core
   of the lazy loading with paging. This header provides the supplemental page 
   table for the system, and you can see the details in little minutes.
   
   Now, before looking those details, let me explain my implementation of
   pintOS virtual memory concepts for this project 4.

   As mentioned in the pintOS manual, the virtual address of pintOS just looks
   like the figure below.

                     31                 12 11          0
                     +--------------------+------------+
                     |  Virtual Page Num  |   Offset   |
                     +--------------------+------------+
   
   And the format of physical address is very similar to this.

                     31                 12 11          0
                     +--------------------+------------+
                     | Physical Frame Num |   Offset   |
                     +--------------------+------------+

   The virtual address is translated to the corresponding physical address
   via the page directory and the page table. These two are already provided
   by the basic pintOS, but the topic(problem) of this phase is how to apply
   the lazy loading concept with paging & replacement & memory mapping to this
   naive pintOS system, by following these steps below.

   (1) First, we need to implement a supplemental page table which is the 
       virtual(logical-side) page table of each thread.
     ~> 'vm/page.h(this header)' takes in charge of this part, with a hash
        and the highly sophisticated page table entry format(structure).

   (2) Second, we need to implement the lazy loading mechanisms by declaring
       a frame structure and the table(list) of those frames. In this step,
       we also have to consider a page(frame) replacement with swapping. 
       Maybe the hardest part of this project 4 phase.
     ~> 'vm/frame.h' and 'vm/swap.h' takes in charge of this part. The former
        provides a LRU(Least Recently Used)-based frame list, and the latter
        provides a swap table representation via bitmap and block structure.

   (3) After those two consequtive steps, we can complete the lazy loading.
       However, this is not the end of this phase, cause we also need to
       implement a memory mapping concepts (some testcases use mmap() call).
     ~> This is easy part. 'vm/mmap.h' gives crucial memory mapping routines.
        'syscall.h' in userprog directory will use this routines.

   (4) Replace the previous naive loading mechanisms with these newly provided
       lazy loading mechanisms from (1) ~ (3), in 'process.h', 'exception.h',
       etc
   
   You can see a detailed description of these steps in the attached report.
   Now, let's get back to this 'page.h' file. Look at the below!            */

/* Type of the page. */
typedef enum { BINARY, MAPPED, SWAPPED } pt_type;

/* Structure below is a format of the entry of the 'supplemental page 
   table' (From now on, I'm gonna call this as just 'page table'). 
   That is, each page table is implemented via this structure, for forming
   a hash table. The reason why a hash table is selected as data structure
   of page table is because it's simple and fast to search and modify. */
struct pt_entry 
{
  /* Information about the page. */
  void *vaddr;                  /* VPN(Virtual Page Number). */
  pt_type type;                 /* Type of page indicated by this PTE. */
  bool is_loaded;               /* Is this page loaded onto physical memory? */
  bool writable;                /* Is it OK to write to this page? */

  /* Variables about file mapped to this page. */
  struct file *file;            /* Pointer to the mapped file. */
  size_t read_bytes;            /* Number of bytes written on page. */
  size_t zero_bytes;            /* Number of rest of bytes of that page. */
  size_t offset;                /* Current file position of the file. */

  /* If this page is mapped to disk(swapping). */
  size_t swap_slot;             /* Index of the slot for swapping this. */

  /* Used for hash operations. */
  struct hash_elem elem;        /* Hash element for each page table. */

  /* If this page is used for the memory mapping. */
  struct list_elem mm_elem;     /* Iterator for the mmap list. */
};

/* These six functions are interfaces of this header. The main user
   of this header is 'process.c', and 'syscall.c' uses this as well,
   especially in the subroutines of lazy loading implementation.  */
void pt_init (struct hash *pt);
struct pt_entry *pt_find_entry (void *vaddr);
bool pt_delete_entry (struct hash *pt, struct pt_entry *pte);
bool pt_insert_entry (struct hash *pt, struct pt_entry *pte);
struct pt_entry *pt_create_entry (void *vaddr, pt_type type, bool writable, bool is_loaded,
    struct file *file, size_t offset, size_t read_bytes, size_t zero_bytes);
void pt_destroy (struct hash *pt);

#endif
