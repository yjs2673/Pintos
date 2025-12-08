#include "vm/frame.h"
#include "vm/swap.h"
#include "lib/string.h"
#include "threads/malloc.h"

struct list frame_list;
struct list_elem *frame_clock;
/* These six protected procedures are methods for managing the frame 
   table in the pintOS system. I'm gonna call these functions as 
   'frame table subroutines' sometimes in the comments below. */
static void ft_insert_frame (struct frame *frame);
static void ft_delete_frame (struct frame *frame);
static struct frame *ft_find_frame (void *kaddr);
static struct list_elem *ft_clocking (void);
static struct frame *ft_get_unaccessed_frame (void);
static void ft_evict_frame (void);

/* For the synchronization of accessing frame table. Note that when this 
   mutex lock is used is not the beginning and end of each frame table 
   subroutines, but the front and back of the call instruction of each 
   subroutines, because interfaces that this header provides use those frame 
   table subroutines in a nested fasion in some cases, which could cause a 
   subtle synchronization error that can be detected by 'make check' via 
   'lock_held_by_current_thread' assertion. Thus, remember this point.*/
struct lock frame_lock;

/* Initialize the frame table, binary semaphore, and iterator,
   which are the crucial data structures for the replacement. */
void 
ft_init (void)
{
  frame_clock = NULL;
  list_init (&frame_list);
  lock_init (&frame_lock);
  //printf("DEBUG: frame_lock address is %p\n", &frame_lock);
}

/* It creates a new physical frame and initializes some metadata about 
   it. That is, this function completely replaces 'palloc_get_page' func
   used in the previous phase (especially in 'userprog/process.c' file).

   The main job is surely the frame allocation, just like the previous one,
   but the lazy loading concepts applied to here. That is, the frame will
   be allocated, but there can be a frame from the swap space(a.k.a. page
   replacement concepts), and it is managed by the supplemental page table
   also (possibly). 
   
   * ALERT: Note that the pintOS usually calls '(physical) frame' just
     as 'page'. Thus, a word 'page' in here is in fact a 'frame'. We should
     keep in mind it when read the below codes. */
struct frame *
alloc_page (enum palloc_flags flags)
{
  struct frame *page; // page == frame //
  if (!(page = (struct frame *)malloc(sizeof(struct frame)))) 
    return NULL;

  memset(page, 0, sizeof(struct frame));
  page->thread = thread_current ();
  page->kaddr = palloc_get_page (flags);
  
  /* If there's no enough space for the allocation, then 
     evict the specific frame from the frame table, and by 
     this eviction, there will be a new physical frame. */
  while (page->kaddr == NULL)
    {
      lock_acquire (&frame_lock);
      ft_evict_frame ();
      lock_release (&frame_lock);
      page->kaddr = palloc_get_page (flags);
    }  

  /* Insert the newly created frame into the frame table. */
  lock_acquire (&frame_lock);
  ft_insert_frame (page);
  lock_release (&frame_lock);

  return page;
}

/* It frees a frame indicated by the passed physical address. That is,
   remove it from the frame table, from the page directory, and deallocate
   it. During this procedure, there should be a mutual exclusion.

   * ALERT: Note that the pintOS usually calls '(physical) frame' just
     as 'page'. Thus, a word 'page' in here is in fact a 'frame'. We should
     keep in mind it when read the below codes. */
void 
free_page (void *kaddr)
{
  struct frame *page;

  lock_acquire (&frame_lock);

  if ((page = ft_find_frame (kaddr)) != NULL)
    {
      ft_delete_frame (page);
      pagedir_clear_page (page->thread->pagedir, page->pte->vaddr);
      palloc_free_page (page->kaddr);
      free (page);
    }

  lock_release (&frame_lock);
}

/* Load a file from the disk onto the physical memory. After loading,
   the remaining part of the given frame will be set to zero. */
bool 
load_file_to_page (void *kaddr, struct pt_entry *pte)
{
  bool success; 

  /* Read(load) the file onto the memory. */
  size_t read_byte = pte->read_bytes;
  size_t temp = (size_t)file_read_at (pte->file, 
    kaddr, pte->read_bytes, pte->offset);
  
  /* Set all the remaining bytes of that frame to zero,
     only if the file read operation was successful. */
  success = (read_byte == temp);
  if (success)
    memset (kaddr + pte->read_bytes, 0, pte->zero_bytes);

  return success;
}


/* Push the selected page(frame) into the back of the frame table. 
   Parameter 'frame' indicates a frame selected upon the LRU policy. */
static void
ft_insert_frame (struct frame *frame)
{
  list_push_back (&frame_list, &(frame->frame_elem));
}

/* Delete the list entry(frame) from the frame table. The target 
   frame must be equal to the current global clock iterator. */
static void
ft_delete_frame (struct frame *frame)
{
  struct list_elem *entry, *ret;

  entry = &(frame->frame_elem);
  ret = list_remove (entry);

  /* If the deleted element is equal to the current global 
     clock iterator, then update it to the next one(frame). */
  if (entry == frame_clock)
    frame_clock = ret;
}

/* Find the corresponding frame from the frame table, based
   on the given physical address passed from the caller. */
static struct frame *
ft_find_frame (void *kaddr)
{
  struct list_elem *iter; struct frame *entry;

  for (iter = list_begin (&frame_list); 
      iter != list_end (&frame_list);
      iter = list_next (iter))
  {
    entry = list_entry(iter, struct frame, frame_elem);

    /* First-Fit policy. */
    if (entry->kaddr == kaddr)
      return entry;
  }

  return NULL;
}

/* Cycle(clock) the frame table, by making the current global 
   iterator move to the next position (in a circular way). */
static struct list_elem *
ft_clocking (void)
{
  /* If the iterator reaches the end of the list, then get 
     back to the front of the swap table (list). */
  if ((frame_clock == NULL) || (frame_clock == list_end (&frame_list)))
  {
    if (!list_empty (&frame_list)) 
      frame_clock = list_begin (&frame_list);

    return frame_clock;
  }

  /* If not, just move to the next. If the next one is the end
     of the table (list), then do this procedure once again. */
  frame_clock = list_next (frame_clock);
  if (frame_clock == list_end (&frame_list))
    frame_clock = ft_clocking ();
  
  return frame_clock;
}

/* Get the first unaccessed frame from the frame table, based on 
   the LRU(Least Recently Used) policy. To implement this policy,
   we can use some useful functions defined in the 'pagedir.h',
   which provides routines to check accesses of given page(frame). */
static struct frame *
ft_get_unaccessed_frame (void)
{
  struct list_elem *g_iter; struct frame *entry;

  /* Find all the pages whose accessed bit is true, and set 
     those bits as false. Keep doing this until we first find 
     the page whose accessed bit is false. (in the frame table) */
  while (1)
  {
    g_iter = ft_clocking ();
    entry = list_entry(g_iter, struct frame, frame_elem);

    if (!(pagedir_is_accessed (entry->thread->pagedir, entry->pte->vaddr)))
      return entry;

    pagedir_set_accessed (entry->thread->pagedir, entry->pte->vaddr, 0);
  }
}

/* If there's a need for eviction of the frame, then search the unaccessed
   frame from the frame table with clock algorithm. After find it, then
   check the dirtiness of that frame and the type of the mapped PTE, and
   perform the corresponding routine for the dirtiness and the type.
   (Therefore, this routine uses an approximate LRU(Least Recently Used) 
   algorithm) */
static void
ft_evict_frame (void)
{
  struct frame *frame;
  bool is_dirty;

  /* Find an unaccessed frame and check the dirtiness of it. */
  frame = ft_get_unaccessed_frame ();
  ft_delete_frame (frame); // 수정
  lock_release (&frame_lock); // 수정
  is_dirty = pagedir_is_dirty (frame->thread->pagedir, frame->pte->vaddr);
  
  /* If the selected frame is from a memory-mapped file, then 
     write data to that file if it's dirty, and evict it. */
  if (frame->pte->type == MAPPED && is_dirty)
    file_write_at (frame->pte->file, frame->kaddr, 
      frame->pte->read_bytes, frame->pte->offset);

  /* If it's from the swap space, then simply swap out. */
  else if (frame->pte->type == SWAPPED)
    frame->pte->swap_slot = swap_out (frame->kaddr);

  /* If it's from the dirty binary file, then swap out. */
  else if (frame->pte->type == BINARY && is_dirty)
    {
      frame->pte->swap_slot = swap_out (frame->kaddr);
      frame->pte->type = SWAPPED;
    }

  /* Frame eviction occurs here, by clearing it from
     the frame table, page directory, memory. */
  frame->pte->is_loaded = false;
  //ft_delete_frame (frame);
  pagedir_clear_page (frame->thread->pagedir, frame->pte->vaddr);
  palloc_free_page (frame->kaddr);
  free (frame);

  lock_acquire (&frame_lock); // 수정
}
