#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <stdio.h>

struct block *swap_block;
struct lock swap_lock;
struct bitmap *swap_bitmap;   

void handle_block(size_t index, void* kaddr, bool r_w){
  
  if(r_w==0)
    for (size_t i = 0; i < BLOCK_MAX; i++)//4KB = 8*512
      block_read (swap_block, index * BLOCK_MAX + i, kaddr + BLOCK_SECTOR_SIZE * i);
  else
    for (size_t i = 0; i < BLOCK_MAX; i++)//4KB = 8*512
      block_write (swap_block, index * BLOCK_MAX + i, kaddr + BLOCK_SECTOR_SIZE * i);
}
void
swap_init(void)
{
  swap_bitmap = bitmap_create (PGSIZE);
  lock_init (&swap_lock);
  if (swap_bitmap == NULL) PANIC ("swap_init");
}

void
swap_in (size_t index, void *kaddr)
{
  if (index == 0) {
    PANIC ("swap_in");
  }
    lock_acquire (&swap_lock);

    swap_block = block_get_role (BLOCK_SWAP);
    --index;
    bitmap_set_multiple (swap_bitmap, index, 1, false);


    handle_block(index, kaddr,0);

    lock_release (&swap_lock);
}

size_t
swap_out (void *kaddr)
{
  size_t index_to_swap;

  lock_acquire (&swap_lock);

  index_to_swap = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  swap_block = block_get_role (BLOCK_SWAP);

  handle_block(index_to_swap, kaddr,1);

  lock_release (&swap_lock);

  return (index_to_swap + 1);
}