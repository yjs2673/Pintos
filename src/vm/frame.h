#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <stdint.h>
#include "lib/kernel/hash.h"
#include "threads/palloc.h"

struct frame 
{ 
  void *kaddr;                  
  struct thread *thread;        
  struct pt_entry *pte;         
  struct list_elem frame_elem;  
};
extern struct list_elem *frame_clock;

void frame_init (void);
static void ft_insert_frame (struct frame *frame);
static void ft_delete_frame (struct frame *frame);
static struct frame *ft_find_frame (void *kaddr);
// struct frame* frame_find(void *paddr);
// static struct frame *ft_get_unaccessed_frame (void);
static void ft_second_chance (void);

struct frame *alloc_page (enum palloc_flags flags);
void free_page (void *kaddr);
bool frame_load_file (void *kaddr, struct pt_entry *pte);

// struct frame* frame_alloc(enum palloc_flags flags);
// void frame_free(void *paddr);

#endif