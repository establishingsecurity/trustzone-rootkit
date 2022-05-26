#include "memory.h"


// linux memory.h
#define PHYS_OFFSET 0x40000000ul
#define PHYSVIRT_OFFSET 0x0001000040000000ul
#define VA_BITS 48
#define VA_MASK ((~0ul << VA_BITS))

#define __is_lm_address_middle(addr)	(!!((addr) & BIT64(VA_BITS - 1)))   // up to v5.4
#define __lm_to_phys_middle(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)  // up to v5.4

#define __is_lm_address_bottom(addr)	(!(((uint64_t)addr) & BIT64(VA_BITS - 1)))
#define __lm_to_phys_bottom_physvirt(addr)      (((addr) + PHYSVIRT_OFFSET))
#define __lm_to_phys_bottom_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)

#define __kimg_to_phys(addr, kimage_voffset)    ((addr) - kimage_voffset)


paddr_t va_to_pa_middle(paddr_t va, paddr_t kimage_voffset);
paddr_t va_to_pa_bottom_physvirt(paddr_t va, paddr_t kimage_voffset);


// This is a workaround for mapping multiple pages,
// mobj_mapped_shm_alloc with num_pages > 1 is broken
int load_pages(paddr_t addr, uint32_t num_pages, struct mobj **mobjs)
{
    int result = 0;
    paddr_t page_ptr;
    struct mobj *mobj;
    for (uint32_t i = 0; i < num_pages; i++)
    {
        page_ptr = (addr & ~PAGE_MASK) + (i * PAGE_SIZE);
        mobj = mobj_mapped_shm_alloc(&page_ptr, 1, 0, 0);
        if (mobj)
            result++;
        mobjs[i] = mobj;
    }
    return result;
}


void free_pages(struct mobj **mobjs, uint32_t num_pages)
{
    for (uint32_t i = 0; i < num_pages; i++)
    {
        struct mobj *mobj = mobjs[i];
        mobj_dec_map(mobj);
        mobj_put(mobj);
    }
}


void mobjs_get_vas(struct mobj **mobjs, uint32_t num_pages, uint64_t **vaddrs)
{
    for (uint32_t i = 0; i < num_pages; i++)
        vaddrs[i] = mobj_get_va(mobjs[i], 0);
}


struct mobj *load_page(paddr_t addr)
{
    paddr_t page_ptr;
    struct mobj *mobj = NULL;

    page_ptr = addr & ~PAGE_MASK;

    mobj = mobj_mapped_shm_alloc(&page_ptr, 1, 0, 0);
    if (!mobj)
        return NULL;

    return mobj;
}


void free_page(struct mobj *mobj)
{
    mobj_dec_map(mobj);
    mobj_put(mobj);
}


bool is_empty_page(uint8_t *addr)
{
    for(size_t i = 0; i < PAGE_SIZE; i++)
        if (*(addr + i) != 0)
            return false;
    return true;
}


bool is_va(paddr_t addr)
{
    return (addr & VA_MASK) == VA_MASK && addr != ~0ul;
}


// up to v5.4
paddr_t va_to_pa_middle(paddr_t va, paddr_t kimage_voffset)
{
    if (__is_lm_address_middle(va))
        return __lm_to_phys_middle(va);
    return __kimg_to_phys(va, kimage_voffset);
}


// v5.5, v5.6
paddr_t va_to_pa_bottom_physvirt(paddr_t va, paddr_t kimage_voffset)
{
    if (__is_lm_address_bottom(va))
        return __lm_to_phys_bottom_physvirt(va);
    return __kimg_to_phys(va, kimage_voffset);
}


const address_translation_function available_translation_functions[] = {&va_to_pa_middle, &va_to_pa_bottom_physvirt};
