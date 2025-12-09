#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* For the synchronization of accessing disk. */
struct lock swap_lock;
/* Provides sector-based I/O access for swapping. */
struct bitmap *swap_bitmap;
struct block *swap_block;

/* Initialize the block and bitmap data structures for swapping. 
   The size of the swap partition of pintOS is 4or8MB and it's 
   gonna be managed by dividing into 4KB(page-size)s.
   This fun*/
void 
swap_init(void)
{
  swap_bitmap = bitmap_create (PGSIZE);

  lock_init (&swap_lock);
}

/* Read all the data of the swap slot indicated by the given 
   index, from the swap space in the disk, and load these data onto 
   the given adrress. Note that we should unset the corresponding
   bit of bitmap to indicate the current slot is swapped in. */
void 
swap_in (size_t index, void *kaddr)
{
  size_t ofs;
  bool idx = false;
  if (index--) idx = true;

  /* Passed index must be bigger than 0. */
  if (idx)
  {
    /* Obtain the block structure. */
    swap_block = block_get_role (BLOCK_SWAP);

    lock_acquire (&swap_lock);

    /* Read(swap in) the corresponding slot. */
    ofs = 0;
    while (ofs < 8)
    {
      block_read (swap_block, (index * 8) + ofs,
        kaddr + (BLOCK_SECTOR_SIZE * ofs));
      ofs++;
    }

    /* Unset the corresponding bit of bitmap. */
    bitmap_set_multiple (swap_bitmap, index, 1, false);

    lock_release (&swap_lock);
  }
  else NOT_REACHED();
}

/* If there're no enough available memory in the system, then
   we should evict the specific frame from the frame table, by
   selecting it based on the LRU policy. In this process, this
   function does a 'swapping out' routine. */
size_t 
swap_out (void *kaddr)
{
  size_t swap_index, ofs;

  /* Obtain the block structure. */
  swap_block = block_get_role (BLOCK_SWAP);
  
  lock_acquire (&swap_lock);

  /* Find the empty slot(0-bit) from the swap table 
     (bitmap), and set(flip) the bit value of that bit. */
  swap_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);

  /* Write(swap out) the evicted frame into the 
     corresponding swap slot in the disk (swap space). */
  ofs = 0;
  while (ofs < 8)
  {
    block_write (swap_block, (swap_index * 8) + ofs,
      kaddr + (BLOCK_SECTOR_SIZE * ofs));
    ofs++;
  }

  lock_release (&swap_lock);
  
  return (++swap_index);
}

/* Free the bit of the indexed swap slot used for swapping.
   That is, this function is called in 'page deallocation' routine
   (in some functions of the 'vm/page.c' file). */
void 
swap_free (size_t index)
{
  bool idx = false;
  if (index--) idx = true;

  if (idx)
  {
    lock_acquire (&swap_lock);

    /* Unset the corresponding bit of bitmap. */
    bitmap_set_multiple (swap_bitmap, index, 1, false);
  
    lock_release (&swap_lock);
  }
}
