#include "vm/mmap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/off_t.h"

/* Binary semaphore providing the mutual exclusion while accessing
   the file system. (declared in 'userprog/syscall.h' file) */
extern struct lock access_lock;

/* Returns the corresponding file pointer from the file descriptor. */
static struct file *mm_get_file (int fd);

/* Returns the corresponding mmap entry from the mmap list of thread. */
static struct mm_entry *mm_get_entry (mapid_t mapid);

/* Memory mapping routine: map a file indicated by the passed descriptor
   onto the physical memory. In the project phase 4 'vm', the pintOS
   system uses this system call while testing, so we should implement this. 
   
   Note that the mmap() system call in 'userprog/syscall.h' calls this
   procedure to perform 'real memory mapping'. */
mapid_t
mm_mapping (int fd, void *addr)
{
  struct mm_entry *mme; struct pt_entry *pte;
  size_t ofs = 0; off_t file_len;
  if (VALIDATION(addr)) return MMAP_ERROR;

  if (!(mme = (struct mm_entry *)malloc(sizeof(struct mm_entry))))
    return MMAP_ERROR;
  
  /* Initialize the newly created mmap entry. During 
     initialization, file access should be protected. */
  mme->mapid = (thread_current ()->mm_list_size)++;

  list_init (&mme->pte_list);
  list_push_back (&(thread_current ()->mm_list), &(mme->elem));

  lock_acquire (&access_lock);
  mme->file = file_reopen (mm_get_file (fd));
  lock_release (&access_lock);

  /* Now, read the mapped file, and load to some pages. */
  file_len = file_length (mme->file);
  while (file_len > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Create a page table entry for this, and push to the
         page table. Note that this is not a loading, this is
         just constructing the page table only. (Lazy Loading) */
      pte = pt_create_entry (addr, MAPPED, true, false,
          mme->file, ofs, page_read_bytes, page_zero_bytes);
      if(!pte) return false;

      pt_insert_entry (&(thread_current ()->pt), pte);

      /* Push the page(entry) to the mapped-page list. */
      list_push_back (&(mme->pte_list), &(pte->mm_elem));

      /* Advance. Note that the offset is updated. */
      addr += PGSIZE;
      ofs += PGSIZE;
      file_len -= PGSIZE;
    }

  return mme->mapid;
}

/* Freeing mmap routine: free the mmap entry and info from the thread,
   by deleting it from the mmap list of that thread, and by deleting 
   all the pages mapped to that mmapped region. In this second deletion,
   the 'real' is that freeing is applied only if the page is dirty.

   Note that the munmap() system call in 'userprog/syscall.h' calls this
   procedure to perform 'real memory map freeing'. */
void 
mm_freeing (mapid_t mapid)
{
  struct list_elem *entry; struct pt_entry *pte;
  struct mm_entry *mme;

  /* Get the corresponding mmap entry of mapid. */
  if (!(mme = mm_get_entry (mapid))) return;
  
  /* From that entry, derive the PTE list of it, and iterate
     with updating if the specific page is dirty and loaded. */
  for (entry = list_begin (&(mme->pte_list)); 
       entry != list_end (&(mme->pte_list));)
  {
    pte = list_entry(entry, struct pt_entry, mm_elem);

    if (pte->is_loaded && 
        pagedir_is_dirty (thread_current ()->pagedir, pte->vaddr))
      {
        lock_acquire (&access_lock);
        
        /* Write(store) the data in mmapped page(memory)
           onto the corresponding file in the disk. */
        size_t read_byte = pte->read_bytes;
        size_t temp = (size_t)file_write_at (pte->file,
          pte->vaddr, pte->read_bytes, pte->offset);

        if (read_byte != temp)
          NOT_REACHED();

        lock_release (&access_lock);

        /* Deallocate only in this case, cause if the target mmapped page
           is not dirty, there's no need to free that physical frame since
           we can reuse that frame in sometimes. (by deleting that PTE) */
        free_page (pagedir_get_page (thread_current ()->pagedir, pte->vaddr)); 
      }

    /* Delete the corresponding PTE from the pt. */
    pte->is_loaded = false;
    entry = list_remove (entry);
    pt_delete_entry (&(thread_current ()->pt), pte);
  }

  list_remove (&(mme->elem));
  free (mme);
}


/* Returns the corresponding file pointer from the file descriptor. */
static struct file *
mm_get_file (int fd)
{
  if (fd < 3 || fd >= FD_MAX) return NULL;

  return thread_current ()->fd[fd];
}

/* Returns the corresponding mmap entry from the mmap list, based on
   the passed mmap identifier. You know, that the mmap list resides
   in each thread created in the system. */
static struct mm_entry *
mm_get_entry (mapid_t mapid)
{
  struct mm_entry *target_entry;
  struct list_elem *entry; 

  for (entry = list_begin (&(thread_current ()->mm_list)); 
      entry != list_end (&(thread_current ()->mm_list)); 
      entry = list_next (entry))
  {
    target_entry = list_entry (entry, struct mm_entry, elem);
    if (target_entry->mapid == mapid) 
      return target_entry;
  }

  return NULL;
}
