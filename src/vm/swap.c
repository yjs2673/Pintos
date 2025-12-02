#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include <bitmap.h>
#include <debug.h>

/* 페이지 하나(4KB)를 저장하기 위해 필요한 디스크 섹터 수 (512B * 8 = 4KB) */
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/* 스왑 디스크 장치 구조체 */
static struct block *swap_block;

/* 스왑 슬롯 사용 여부를 관리하는 비트맵
   1: 사용 중, 0: 비어 있음 */
static struct bitmap *swap_map;

/* 스왑 테이블 접근 동기화를 위한 락 */
static struct lock swap_lock;

/* 스왑 시스템 초기화 함수
   main.c 혹은 init.c 등에서 시스템 시작 시 호출되어야 함 */
void
swap_init (void)
{
  /* 스왑 영역을 가진 블록 디바이스를 가져옴 */
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL)
    return;

  /* 스왑 디스크의 크기에 맞춰 비트맵 생성
     전체 섹터 수 / 페이지 당 섹터 수 = 관리할 수 있는 총 페이지 수 */
  size_t swap_size = block_size (swap_block) / SECTORS_PER_PAGE;
  swap_map = bitmap_create (swap_size);
  if (swap_map == NULL)
    PANIC ("Bitmap creation failed for swap.");

  /* 모든 슬롯을 false(빈 상태)로 초기화 */
  bitmap_set_all (swap_map, false);
  
  lock_init (&swap_lock);
}

/* Swap Out: 메모리(kaddr) -> 디스크 */
size_t
swap_out (void *kaddr)
{
  /* 스왑 디스크가 없으면 패닉 (혹은 에러 처리) */
  if (swap_block == NULL || swap_map == NULL)
    PANIC ("Swap block or map not initialized.");

  lock_acquire (&swap_lock);

  /* 비트맵에서 빈 슬롯(0)을 찾아 첫 번째 인덱스를 반환하고, 해당 비트를 1로 설정(flip) */
  size_t swap_index = bitmap_scan_and_flip (swap_map, 0, 1, false);
  
  if (swap_index == BITMAP_ERROR)
    PANIC ("Swap disk is full!"); // 스왑 공간 부족

  /* 해당 슬롯에 페이지 데이터를 씀 (8개 섹터에 나누어 씀) */
  for (int i = 0; i < SECTORS_PER_PAGE; i++)
    {
      block_write (swap_block,
                   swap_index * SECTORS_PER_PAGE + i,
                   (uint8_t *) kaddr + i * BLOCK_SECTOR_SIZE);
    }

  lock_release (&swap_lock);

  return swap_index;
}

/* Swap In: 디스크(used_index) -> 메모리(kaddr) */
void
swap_in (size_t used_index, void *kaddr)
{
  if (swap_block == NULL || swap_map == NULL)
    PANIC ("Swap block or map not initialized.");

  lock_acquire (&swap_lock);

  /* 해당 슬롯이 실제로 사용 중인지 확인 */
  if (bitmap_test (swap_map, used_index) == false)
    PANIC ("Trying to swap in a free slot.");

  /* 디스크에서 데이터를 읽어 메모리에 씀 */
  for (int i = 0; i < SECTORS_PER_PAGE; i++)
    {
      block_read (swap_block,
                  used_index * SECTORS_PER_PAGE + i,
                  (uint8_t *) kaddr + i * BLOCK_SECTOR_SIZE);
    }

  /* 읽어온 후 해당 스왑 슬롯을 비움 (0으로 설정) */
  bitmap_set (swap_map, used_index, false);

  lock_release (&swap_lock);
}

/* 스왑 슬롯 해제 (프로세스 종료 시 등 데이터가 필요 없을 때 사용) */
void
swap_free (size_t used_index)
{
  if (swap_block == NULL || swap_map == NULL) return;

  lock_acquire (&swap_lock);
  if (bitmap_test (swap_map, used_index))
    {
      bitmap_set (swap_map, used_index, false);
    }
  lock_release (&swap_lock);
}