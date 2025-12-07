#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include <stdint.h>
#include "debug.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"

#define VM_BIN  0x00
#define VM_FILE 0x01
#define VM_ANON 0x02

typedef enum { 
    BINARY, 
    ANON, 
    SWAPPED 
} pt_type;

struct pt_entry 
{
  struct file *file;            
  size_t offset;                
  size_t read_bytes;            
  size_t zero_bytes;            

  /* 가상 주소 및 상태 정보 */
  void *vaddr;                  
  size_t swap_slot;             
  
  /* 상태 플래그 */
  bool is_loaded;               
  bool writable;                
  pt_type type;                 

  struct hash_elem elem;        
};

void pt_init (struct hash *pt);
struct pt_entry *pt_find_entry (void *vaddr);
struct pt_entry *pt_lookup_entry (struct hash *pt, void *vaddr);
bool pt_insert_entry (struct hash *pt, struct pt_entry *pte);
bool pt_delete_entry (struct hash *pt, struct pt_entry *pte);
void pt_destroy (struct hash *pt);

#endif