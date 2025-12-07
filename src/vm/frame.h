#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <stdint.h>
#include "lib/kernel/hash.h"
#include "threads/palloc.h"

struct frame 
{ 
  void *kaddr;      
  struct pt_entry *pte;            
  struct thread *thread;
  struct list_elem frame_elem;      
};

extern struct list_elem *frame_clock;

void frame_init (void);

struct list_elem *vm_frame_next ();
static struct frame* vm_find_frame (void *kaddr);

static void vm_insert_frame (struct frame *frame);
static void vm_delete_frame (struct frame *frame);

static void vm_second_chance (void);

bool load_file_to_page (void *kaddr, struct pt_entry *pte);
struct frame *vm_alloc_page (enum palloc_flags flags);
void vm_free_page (void *kaddr);

#endif