#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <stdio.h>

struct block *swap_block;
struct lock swap_lock;
struct bitmap *swap_bitmap;

void swap_init (void) {
  lock_init (&swap_lock);
  
  /* 페이지 크기에 맞게 비트맵 생성 */
  swap_bitmap = bitmap_create (PGSIZE);
  
  if (swap_bitmap == NULL) PANIC ("swap_init: bitmap creation failed");
}

size_t swap_out (void *kaddr) {
  size_t slot_idx;
  
  lock_acquire (&swap_lock);

  /* 빈 슬롯 찾기 */
  slot_idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  
  if (slot_idx == BITMAP_ERROR) PANIC ("swap_out: no swap slot available");

  swap_block = block_get_role (BLOCK_SWAP);

  size_t i = 0;
  block_sector_t start_sector = slot_idx * BLOCK_MAX; // BLOCK_MAX = 8

  while (i < BLOCK_MAX) {
    void *buffer_pos = kaddr + (i * BLOCK_SECTOR_SIZE);
    block_write (swap_block, start_sector + i, buffer_pos);
    i++;
  }

  lock_release (&swap_lock);

  return (slot_idx + 1);
}

void swap_in (size_t index, void *kaddr) {
  if (index == 0) PANIC ("swap_in: invalid index 0");

  lock_acquire (&swap_lock);

  /* 실제 비트맵 인덱스로 변환 (index - 1) */
  size_t real_idx = index - 1;

  swap_block = block_get_role (BLOCK_SWAP);
  
  /* 비트맵 상태 업데이트 */
  bitmap_set_multiple (swap_bitmap, real_idx, 1, false);

  for (size_t i = 0; i < BLOCK_MAX; i++) {
    block_sector_t sec_no = (real_idx * BLOCK_MAX) + i;
    void *read_addr = kaddr + (i * BLOCK_SECTOR_SIZE);
      
    block_read (swap_block, sec_no, read_addr);
  }

  lock_release (&swap_lock);
}