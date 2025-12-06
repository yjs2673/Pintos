#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include <stdint.h>
#include "debug.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

typedef enum { BINARY, ANON, SWAPPED } pt_type;

struct pt_entry 
{
  void *vaddr;                  
  pt_type type;                 
  
  size_t offset;                
  size_t read_bytes;            
  size_t zero_bytes;            
  
  bool writable;                
  bool is_loaded;               

  struct hash_elem elem;        

  struct file *file;            
  size_t swap_slot;             
};

void pt_init (struct hash *pt);
void pt_destroy (struct hash *pt);
bool pt_insert_entry (struct hash *pt, struct pt_entry *pte);
bool pt_delete_entry (struct hash *pt, struct pt_entry *pte);
struct pt_entry *pt_find_entry (void *vaddr);
struct pt_entry *pt_lookup_entry (struct hash *pt, void *vaddr);

#endif