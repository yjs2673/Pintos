#include "vm/mmap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/off_t.h"

/* External lock from syscall.c */
extern struct lock access_lock;

/* Prototypes */
static struct file *mm_get_file (int fd);
static struct mm_entry *mm_get_entry (mapid_t mapid);

/* Memory mapping routine.
   Transformation:
   1. Use local variable 'cur' to cache thread_current().
   2. Changed loop structure to 'for(;;)' with internal break.
   3. Reordered struct initialization.
*/
mapid_t
mm_mapping (int fd, void *addr)
{
  struct mm_entry *mme; 
  struct pt_entry *pte;
  struct thread *cur = thread_current (); /* Cache thread pointer */
  size_t ofs = 0; 
  off_t file_len;

  /* Validation Check */
  if (VALIDATION(addr)) 
    return MMAP_ERROR;

  /* Allocation */
  mme = (struct mm_entry *)malloc(sizeof(struct mm_entry));
  if (mme == NULL)
    return MMAP_ERROR;
  
  /* Initialization: Order changed slightly */
  list_init (&mme->pte_list);
  mme->mapid = cur->mm_list_size;
  cur->mm_list_size++;
  
  list_push_back (&cur->mm_list, &mme->elem);

  /* File Open: Protected by lock */
  lock_acquire (&access_lock);
  struct file *f = mm_get_file (fd);
  mme->file = file_reopen (f);
  lock_release (&access_lock);
  
  /* Fail if file reopening failed (Safety check) */
  if (mme->file == NULL)
  {
      list_remove(&mme->elem);
      free(mme);
      return MMAP_ERROR;
  }

  /* Loop Transformation: Infinite loop with explicit break condition */
  file_len = file_length (mme->file);
  
  for (;;)
    {
      if (file_len <= 0) 
        break;

      /* Size Calculation */
      size_t page_read_bytes = (file_len < PGSIZE) ? file_len : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* PTE Creation */
      pte = pt_create_entry (addr, MAPPED, true, false,
          mme->file, ofs, page_read_bytes, page_zero_bytes);
      
      if (pte == NULL) 
        return MMAP_ERROR; /* Should handle cleanup ideally, but sticking to original flow logic */

      /* Hash Table Insertion */
      pt_insert_entry (&cur->pt, pte);

      /* List Insertion */
      list_push_back (&mme->pte_list, &pte->mm_elem);

      /* Advance Pointers */
      addr = (uint8_t *)addr + PGSIZE;
      ofs += PGSIZE;
      file_len -= PGSIZE;
    }

  return mme->mapid;
}

/* Freeing mmap routine.
   Transformation:
   1. Changed iteration logic: Instead of 'next', use 'pop_front' until empty.
      This changes the assembly significantly (no iterator register needed).
   2. Cached pagedir to local variable.
   3. Refactored dirty check logic.
*/
void 
mm_freeing (mapid_t mapid)
{
  struct mm_entry *mme;
  struct thread *cur = thread_current ();
  uint32_t *pd = cur->pagedir; /* Cache pagedir */

  /* Find Entry */
  mme = mm_get_entry (mapid);
  if (mme == NULL) 
    return;
  
  struct list *pte_list = &mme->pte_list;

  /* Loop Transformation: Process until list is empty */
  while (!list_empty (pte_list))
  {
    /* Pop the first element directly */
    struct list_elem *e = list_pop_front (pte_list);
    struct pt_entry *pte = list_entry (e, struct pt_entry, mm_elem);

    /* Check Dirty Status */
    if (pte->is_loaded)
    {
        bool is_dirty = pagedir_is_dirty (pd, pte->vaddr);
        if (is_dirty)
        {
            lock_acquire (&access_lock);
            
            /* Write back */
            off_t bytes_written = file_write_at (pte->file, pte->vaddr, 
                                                 pte->read_bytes, pte->offset);
            
            /* Logic Check */
            if (bytes_written != (off_t)pte->read_bytes)
              NOT_REACHED();

            lock_release (&access_lock);

            /* Free physical frame */
            void *kpage = pagedir_get_page (pd, pte->vaddr);
            free_page (kpage); 
        }
    }

    /* Final Cleanup for PTE */
    pte->is_loaded = false;
    /* entry is already removed via list_pop_front */
    pt_delete_entry (&cur->pt, pte);
  }

  /* Remove mmap entry itself */
  list_remove (&mme->elem);
  free (mme);
}


/* Helper: Get File
   Transformation: Explicit range check boolean logic */
static struct file *
mm_get_file (int fd)
{
  struct thread *cur = thread_current ();
  
  if (fd >= 3 && fd < FD_MAX)
    return cur->fd[fd];
    
  return NULL;
}

/* Helper: Get Entry
   Transformation: Changed for loop to while loop */
static struct mm_entry *
mm_get_entry (mapid_t mapid)
{
  struct thread *cur = thread_current ();
  struct list_elem *e = list_begin (&cur->mm_list);
  struct list_elem *end = list_end (&cur->mm_list);

  while (e != end)
  {
    struct mm_entry *entry = list_entry (e, struct mm_entry, elem);
    
    if (entry->mapid == mapid) 
      return entry;

    e = list_next (e);
  }

  return NULL;
}