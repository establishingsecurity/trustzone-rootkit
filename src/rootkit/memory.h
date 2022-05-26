#ifndef ROOTKIT_MEMORY_H
#define ROOTKIT_MEMORY_H

#include <mm/mobj.h>
#include <mm/core_mmu.h>


#define PAGE_OFFSET 0xffff800000000000ul

// only valid when using 4k pages
#define PAGE_SIZE SMALL_PAGE_SIZE
#define PAGE_MASK SMALL_PAGE_MASK
#define PAGE_OFFSET_MASK 0x0fff

#define NULL_PADDR 0ul
#define ERROR_ADDR (-1ull)
#define NUM_TRANSLATION_FUNCTIONS 2

int load_pages(paddr_t addr, uint32_t num_pages, struct mobj **mobjs);
void free_pages(struct mobj **mobjs, uint32_t num_pages);
void mobjs_get_vas(struct mobj **mobjs, uint32_t num_pages, uint64_t **vaddrs);
struct mobj *load_page(paddr_t addr);
void free_page(struct mobj *mobj);
bool is_empty_page(uint8_t *addr);
bool is_va(paddr_t addr);

typedef paddr_t (*address_translation_function)(paddr_t, paddr_t);
extern const address_translation_function available_translation_functions[NUM_TRANSLATION_FUNCTIONS];

#endif
