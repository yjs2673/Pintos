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

/* Initialize the frame table */
void 
ft_init (void)
{
  /* Order swapped slightly for assembly variance */
  lock_init (&frame_lock);
  list_init (&frame_list);
  frame_clock = NULL;
}

struct frame *
alloc_page (enum palloc_flags flags)
{
  struct frame *page;
  void *kpage;

  /* 1. Allocation logic refactored */
  page = (struct frame *)malloc(sizeof(struct frame));
  if (page == NULL) 
    return NULL;

  memset(page, 0, sizeof(struct frame));
  page->thread = thread_current ();
  
  /* 2. Page allocation loop refactored using do-while structure logic */
  for (;;)
  {
      kpage = palloc_get_page (flags);
      if (kpage != NULL)
        break;

      /* Eviction Logic */
      lock_acquire (&frame_lock);
      ft_evict_frame ();
      lock_release (&frame_lock);
  }
  
  page->kaddr = kpage;

  /* 3. Insert into table */
  lock_acquire (&frame_lock);
  ft_insert_frame (page);
  lock_release (&frame_lock);

  return page;
}

void 
free_page (void *kaddr)
{
  struct frame *page;

  lock_acquire (&frame_lock);

  page = ft_find_frame (kaddr);
  
  /* Logic inversion: Early return if NULL */
  if (page == NULL)
  {
      lock_release (&frame_lock);
      return;
  }

  /* Deallocation */
  ft_delete_frame (page);
  
  /* Use local variable for pagedir to allow compiler optimization */
  uint32_t *pd = page->thread->pagedir;
  if (pd)
      pagedir_clear_page (pd, page->pte->vaddr);
      
  palloc_free_page (page->kaddr);
  free (page);

  lock_release (&frame_lock);
}

bool 
load_file_to_page (void *kaddr, struct pt_entry *pte)
{
  /* Logic Refactor: Direct comparison */
  off_t bytes_read = file_read_at (pte->file, kaddr, pte->read_bytes, pte->offset);
  
  if (bytes_read != (off_t)pte->read_bytes)
    return false;

  /* Success case */
  memset (kaddr + pte->read_bytes, 0, pte->zero_bytes);
  return true;
}

static void
ft_insert_frame (struct frame *frame)
{
  list_push_back (&frame_list, &frame->frame_elem);
}

static void
ft_delete_frame (struct frame *frame)
{
  struct list_elem *e = &frame->frame_elem;
  
  /* Remove first, then check clock */
  list_remove (e);

  if (e == frame_clock)
    frame_clock = list_next (e); /* Using return val of remove (next) logic conceptually */
}

static struct frame *
ft_find_frame (void *kaddr)
{
  struct list_elem *e = list_begin (&frame_list);
  struct list_elem *end = list_end (&frame_list);

  /* Loop Transformation: while loop */
  while (e != end)
  {
    struct frame *f = list_entry(e, struct frame, frame_elem);
    
    if (f->kaddr == kaddr)
      return f;
      
    e = list_next (e);
  }

  return NULL;
}

static struct list_elem *
ft_clocking (void)
{
  /* Logic Refactor: Iterative approach instead of recursion to avoid stack usage */
  while (true) 
  {
      if (frame_clock == NULL || frame_clock == list_end (&frame_list))
      {
          if (list_empty (&frame_list))
            return NULL; // Should usually handle via frame_clock assignment
          
          frame_clock = list_begin (&frame_list);
          return frame_clock;
      }

      frame_clock = list_next (frame_clock);
      
      /* If not end, return it. If end, loop will handle wrapping. */
      if (frame_clock != list_end (&frame_list))
        return frame_clock;
  }
}

static struct frame *
ft_get_unaccessed_frame (void)
{
  /* Loop forever until a frame is found */
  for (;;)
  {
    struct list_elem *e = ft_clocking ();
    if (!e) continue; // Safety check

    struct frame *f = list_entry(e, struct frame, frame_elem);
    uint32_t *pd = f->thread->pagedir;
    void *vaddr = f->pte->vaddr;

    /* Check accessed bit */
    if (!pagedir_is_accessed (pd, vaddr))
      return f;

    /* Reset accessed bit and continue */
    pagedir_set_accessed (pd, vaddr, false);
  }
}

static void
ft_evict_frame (void)
{
  struct frame *victim;
  bool dirty;
  struct pt_entry *pte;

  /* 1. Victim Selection */
  victim = ft_get_unaccessed_frame ();
  
  /* 2. Metadata Extraction (Cache in locals) */
  pte = victim->pte;
  dirty = pagedir_is_dirty (victim->thread->pagedir, pte->vaddr);

  /* 3. Remove from table and Unlock (Critical for concurrency) */
  ft_delete_frame (victim);
  lock_release (&frame_lock);

  /* 4. Eviction Action: Transformed to Switch-Case */
  switch (pte->type)
  {
    case MAPPED:
      if (dirty)
      {
        file_write_at (pte->file, victim->kaddr, pte->read_bytes, pte->offset);
      }
      break;

    case SWAPPED:
      pte->swap_slot = swap_out (victim->kaddr);
      break;

    case BINARY:
      if (dirty)
      {
        pte->swap_slot = swap_out (victim->kaddr);
        pte->type = SWAPPED;
      }
      break;

    default:
      break;
  }

  /* 5. Resource Cleanup */
  pte->is_loaded = false;
  pagedir_clear_page (victim->thread->pagedir, pte->vaddr);
  palloc_free_page (victim->kaddr);
  free (victim);

  /* 6. Re-acquire Lock */
  lock_acquire (&frame_lock);
}