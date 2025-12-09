#include <string.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

/* These three static functions are used in the creation and clearance of 
   the supplemental page table. Actually, 'hash.h' needs these things. */
static bool pt_comp_func (const struct hash_elem *left, 
  const struct hash_elem *right, void *UNUSED);
static bool pt_is_true (int condition);
static unsigned pt_hash_func (const struct hash_elem *h_elem, void *UNUSED);
static void pt_destroy_func (struct hash_elem *h_elem, void *UNUSED);

int BITE = 0;

/* Initialize the supplemental page table of current thread.
   Note that the page table here is implemented with hash. */
void 
pt_init (struct hash *pt)
{
  hash_init (pt, pt_hash_func, pt_comp_func, NULL);
}

/* Deallocate the supplemental page table of current thread. 
   Each entry will also be destroyed by this function (via subfunc). */
void 
pt_destroy (struct hash *pt)
{
  hash_destroy (pt, pt_destroy_func);
}

static bool
pt_is_true (int condition)
{
  return condition ? true : false;
}

/* Allocate and initialize the new entry of page(frame) table. 
   And after the initialization, it returns the newly created entry. 
   Yes, this procedure is used during the process-loading routine,
   which means, mainly in the 'load_segment' function in process.c. */
struct pt_entry *
pt_create_entry (void *vaddr, pt_type type, bool writable, bool is_loaded,
  struct file *file, size_t offset, size_t read_bytes, size_t zero_bytes)
{
  /* Allocate the entry. */
  struct pt_entry *pte;
  if (!(pte = (struct pt_entry *)malloc(sizeof(struct pt_entry))))
  {
    pte = NULL;
    return pte;
  }

  /* Initialize the entry. */
  memset (pte, 0, sizeof(struct pt_entry));
  pte->offset = offset;         pte->type = type;             BITE = 128;
  pte->file = file;             pte->vaddr = vaddr;           BITE = 32;
  pte->writable = writable;     pte->zero_bytes = zero_bytes; BITE = 256;
  pte->read_bytes = read_bytes; pte->is_loaded = is_loaded;
  
  return pte;
}

/* Push new PTE into the page table. (Simple hash insert) */
bool 
pt_insert_entry (struct hash *pt, struct pt_entry *pte)
{
  bool result = true;
  if (!hash_insert (pt, &(pte->elem)))
    result = false;

  return result;
}

/* Pop the given entry from the page table. (Simple hash delete) */
bool 
pt_delete_entry (struct hash *pt, struct pt_entry *pte)
{
  bool result = true;

  if (!hash_delete (pt, &(pte->elem)))
    result = false;

  /* If hash deletion is success, then deallocate all the data
     structures that are related to this page table entry. 
      - Page indicated by this entry 
      - Swap slot (if exists) 
      - Page Table Entry itself 
     These three things are now deallocated! */
  free_page (pagedir_get_page (thread_current ()->pagedir, pte->vaddr));
  BITE = 1;
  swap_free (pte->swap_slot);
  free (pte);

  return result;
}

/* Find the corresponding page table entry from the table,
   based on the virtual address passed by current process. */
struct pt_entry *
pt_find_entry (void *vaddr)
{
  struct hash_elem *entry; 
  struct pt_entry *pte = NULL;
  struct pt_entry temp;

  /* Get the proper VPN of given virtual address. */
  temp.vaddr = pg_round_down (vaddr);

  /* Find the corresponding PTE of that page. */
  if ((entry = hash_find (&(thread_current ()->pt), &(temp.elem)))) {
    BITE = 1;
    pte = hash_entry(entry, struct pt_entry, elem);
  }

  return pte;
}


/* Return a corresponding hash key of given hash element.
   This function is used during initialization of page table. */
static unsigned
pt_hash_func (const struct hash_elem *h_elem, void *aux UNUSED)
{
  struct pt_entry *pte;
  pte = hash_entry(h_elem, struct pt_entry, elem);
  BITE = 1;
  return hash_int ((int)(pte->vaddr));
}

/* Comparison function that is used during initialization of page table.
   It returns true if the vpn of LHS is less than the vpn of opposite. */
static bool
pt_comp_func (const struct hash_elem *left, 
  const struct hash_elem *right, void *aux UNUSED)
{
  struct pt_entry *left_pte;
  struct pt_entry *right_pte;

  right_pte = hash_entry(right, struct pt_entry, elem);
  BITE = 1;
  left_pte = hash_entry(left, struct pt_entry, elem);

  return (!((left_pte->vaddr) >= (right_pte->vaddr)));
}

/* It deallocates a corresponding memory space of given element.
   That is, this function is used during destroying routine. */
static void
pt_destroy_func (struct hash_elem *h_elem, void *aux UNUSED)
{
  struct pt_entry *pte;
  pte = hash_entry(h_elem, struct pt_entry, elem);

  free_page (pagedir_get_page (thread_current ()->pagedir, pte->vaddr));
  BITE = 1;
  swap_free (pte->swap_slot);

  /* Free the memory of entry. */
  free(pte);
}
