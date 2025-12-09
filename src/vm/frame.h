#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* As you can see the name of this header file, the main purpose of this
   header is a physical frame allocation, that is, it replaces the naive 
   frame allocation provided by the 'threads/palloc.h' file, with the new
   mechanism that the lazy loading & page replacement concepts applied to.
   
   Thus, in summary, 'frame.h' provides page(frame) allocation routines 
   to users, and inside those routines, page replacement a.k.a swapping
   has been implemented. Let's read sentences right below. */

/* This library provides data structures for the page replacement
   concepts (a.k.a Swapping). We will use a LRU(Least Recently Used)
   policy for this implementation.
   And note that this 'frame' library will work with 'swap' header file
   in the same directory. Various functions in both libraries will be
   used for performing the second chance (clock) algorithm in this pintOS.

   * You should first allocate a swap disk in the 'vm/build' directory
     by 'pintos-mkdisk swap.dsk --swap-size=n' instruction.
  -> swap.dsk will be automatically attached to the hdb1 while booting.

   * Note that the difference between 'frame' and 'swap' is, functions
     in the 'frame.h' manage the frame table by performing list operations.

     In the contrast, functions in 'swap.h' manage the swap table, with
     'actually' accessing to and working on the swap disk, by using the 
     evicted(on LRU) frame prodived from the frame table of 'frame.h'    */

/* Structure below has an information about the frame. You know, this is
   not about the supplemental page table entry, this is about some metadata 
   related to the physical frame. 
   
   * ALERT: Note that the pintOS usually calls '(physical) frame' just
     as 'page'. Thus, the interface of this header like 'alloc_page' uses
     a word 'page', but in fact it's 'frame'. We should keep in mind it. */
struct frame 
{ 
  void *kaddr;                  /* Physical Address of this frame. */
  struct pt_entry *pte;         /* Pointer to the mapped PTE for this. */
  struct list_elem frame_elem;  /* Iterator for the page replacement. */
  struct thread *thread;        /* The thread who uses this frame. */
};

/* Global iterator that cycles the frame table.
   That is, we use a clock algorithm to search for evicting. */
extern struct list_elem *frame_clock;

/* Frame table based on the list structure. */
extern struct list frame_list;

/* These only four functions are interfaces of this header. 
   ft_init should be called in the beginning of the system,
   and the other three will be used in the loading management.
   (page replacement is abstracted inside those functions) */
void ft_init (void);
bool load_file_to_page (void *kaddr, struct pt_entry *pte);
struct frame *alloc_page (enum palloc_flags flags);
void free_page (void *kaddr);

/* In fact, it would be better that loading mechanisms like 'alloc_page' is
   implemented in 'threads/palloc.h' in perspective of its meanings. 
   However, I put these functions here because of project phase division. */

#endif
