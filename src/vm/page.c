#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


/* helper functions */
static unsigned pt_hash (const struct hash_elem *h_elem, void *UNUSED);
static bool pt_cmp (const struct hash_elem *left, const struct hash_elem *right, void *UNUSED);
static void pt_destroy_func (struct hash_elem *h_elem, void *UNUSED);

extern struct lock frame_lock;
/*
lock_acquire(&frame_lock);
lock_release(&frame_lock);


*/
void 
pt_init (struct hash *pt)//완
{
  hash_init (pt, pt_hash, pt_cmp, NULL);
}

void 
pt_destroy (struct hash *pt)//완
{
  
  lock_acquire(&frame_lock);
  hash_destroy (pt, pt_destroy_func);
  lock_release(&frame_lock);

}

bool //0
pt_insert_entry (struct hash *pt, struct pt_entry *pte)
{
  lock_acquire(&frame_lock);
  bool success=hash_insert(pt, &(pte->elem));
  lock_release(&frame_lock);
  return success;
}

bool //완
pt_delete_entry (struct hash *pt, struct pt_entry *pte)
{
  lock_acquire(&frame_lock);
  bool success=hash_delete(pt, &(pte->elem));
  lock_release(&frame_lock);
  if (!success) return false;
  free_page (pagedir_get_page (thread_current ()->pagedir, pte->vaddr));
  free (pte);
  return true;
}

struct pt_entry *
pt_find_entry (void *vaddr)//완
{
  struct pt_entry tmp; 
  struct pt_entry *ve = NULL;
  struct hash_elem *elem;
  tmp.vaddr = pg_round_down(vaddr); //malloc?
  elem = hash_find(&thread_current()->pt, &tmp.elem);
  if(elem) ve = hash_entry(elem, struct pt_entry, elem);
  return ve;//NULL처리?
}


static unsigned//완
pt_hash (const struct hash_elem *h_elem, void *aux UNUSED)
{
  struct pt_entry *pte = hash_entry(h_elem, struct pt_entry, elem);

  return hash_int ((int)(pte->vaddr));
}

static bool//완
pt_cmp (const struct hash_elem *A, 
  const struct hash_elem *B, void *aux UNUSED)
{
  struct pt_entry *a = hash_entry(A, struct pt_entry, elem);
  struct pt_entry *b = hash_entry(B, struct pt_entry, elem);

  return ((a->vaddr) < (b->vaddr));
}

void page_delete(struct pt_entry *pte){//완
    void *paddr = pagedir_get_page(thread_current()->pagedir, pte->vaddr);
    free_page(paddr); //=frame_free
}
static void pt_destroy_func(struct hash_elem *e, void *aux UNUSED){//완
    struct pt_entry *ve = hash_entry(e, struct pt_entry, elem);

    if(ve->is_loaded){
      page_delete(ve);
    }
    free(ve);
}

struct pt_entry *
pt_lookup_entry (struct hash *pt, void *vaddr)
{
    // 기존 pt_find_entry를 재활용하거나 직접 구현
    struct pt_entry tmp;
    struct hash_elem *e;
    tmp.vaddr = pg_round_down(vaddr);
    e = hash_find(pt, &tmp.elem);
    return e != NULL ? hash_entry(e, struct pt_entry, elem) : NULL;
}