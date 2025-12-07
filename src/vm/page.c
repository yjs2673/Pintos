#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static unsigned pt_hash (const struct hash_elem *h_elem, void *aux UNUSED);
static bool pt_cmp (const struct hash_elem *left, const struct hash_elem *right, void *aux UNUSED);
static void pt_destroy_func (struct hash_elem *h_elem, void *aux UNUSED);

extern struct lock frame_lock;

void pt_init (struct hash *pt) {
  if (pt != NULL) hash_init (pt, pt_hash, pt_cmp, NULL);
}

struct pt_entry * pt_find_entry (void *vaddr) {
  struct pt_entry key;
  struct hash_elem *elem;

  key.vaddr = pg_round_down (vaddr);
  
  elem = hash_find (&thread_current ()->pt, &key.elem);

  return (elem != NULL) ? hash_entry (elem, struct pt_entry, elem) : NULL;
}

bool pt_insert_entry (struct hash *pt, struct pt_entry *pte) {
  bool result = false;

  lock_acquire (&frame_lock);
  bool success = hash_insert (pt, &(pte->elem));
  if (success == NULL) result = true;
  lock_release (&frame_lock);

  return success;
}

bool pt_delete_entry (struct hash *pt, struct pt_entry *pte) {
  bool result = false;

  lock_acquire (&frame_lock);
  bool success = hash_delete (pt, &(pte->elem));
  if (success != NULL) result = true;
  lock_release (&frame_lock);

  if (!success) return result;
  vm_free_page (pagedir_get_page (thread_current ()->pagedir, pte->vaddr));
  free (pte);
  return result;
}

void pt_destroy (struct hash *pt) {
  if (pt == NULL) return;

  lock_acquire (&frame_lock);
  hash_destroy (pt, pt_destroy_func);
  lock_release (&frame_lock);
}

static unsigned pt_hash (const struct hash_elem *h_elem, void *aux UNUSED) {
  const struct pt_entry *p = hash_entry (h_elem, struct pt_entry, elem);
  return hash_int ((int) p->vaddr);
}

static bool pt_cmp (const struct hash_elem *left, const struct hash_elem *right, void *aux UNUSED) {
  const struct pt_entry *l = hash_entry (left, struct pt_entry, elem);
  const struct pt_entry *r = hash_entry (right, struct pt_entry, elem);

  return l->vaddr < r->vaddr;
}

static void  pt_destroy_func (struct hash_elem *h_elem, void *aux UNUSED) {
  if (h_elem == NULL) return;
  
  struct pt_entry *ve = hash_entry (h_elem, struct pt_entry, elem);

  if (ve->is_loaded)
    {
      struct thread *cur = thread_current ();
      void *frame_addr = pagedir_get_page (cur->pagedir, ve->vaddr);
      
      if (frame_addr != NULL) vm_free_page (frame_addr);
    }
    
  free (ve);
}