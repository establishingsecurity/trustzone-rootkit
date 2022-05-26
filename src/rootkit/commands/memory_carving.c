#include "memory_carving.h"
#include "common.h"
#include "../memory.h"
#include "../utils.h"

#include <types_ext.h>

#define MAX_TRANSLATION_LEVEL 3
#define TABLE_ADDRESS_MASK 0xFFFFFFFFF000
#define PAGE_ADDRESS_MASK 0xFFFFFFFFF000
#define MIN_BLOCK_TRANSLATION_LEVEL 1
#define MAX_BLOCK_TRANSLATION_LEVEL 2
#define PAGE_TRANSLATION_LEVEL 3

const uint64_t BLOCK_ADRESS_MASKS[MAX_TRANSLATION_LEVEL + 1] = {-1, 0xFFFFC0000000, 0xFFFFFFE00000, -1};


void print_match(char *begin_vaddr);
uint16_t process_page(paddr_t page_addr, char *signature_begin, char *signature_end);
uint16_t process_block(paddr_t block_base_addr, uint8_t level, char *signature_begin, char *signature_end);
uint16_t process_translation_level(paddr_t level_base_addr, uint8_t level, char *signature_begin, char *signature_end);
uint16_t signature_search(paddr_t swapper_pg_dir_addr, char *signature_begin, char *signature_end);
paddr_t find_swapper_pg_dir(paddr_t swapper_pg_dir_upper_bound_addr);


void print_match(char *begin_vaddr)
{
    trace_ext_puts(begin_vaddr);
    trace_ext_puts("\n");
}


uint16_t process_page(paddr_t page_addr, char *signature_begin, char *signature_end)
{
    uint16_t count = 0;

    struct mobj *mobj = load_page(page_addr);
    if (!mobj)
        return count;

    uint64_t *vaddr = mobj_get_va(mobj, 0);

    void *begin_vaddr = find(vaddr, PAGE_SIZE, signature_begin, strlen(signature_begin));
    if (begin_vaddr != NULL)
    {
        void *end_vaddr = find(begin_vaddr, PAGE_SIZE - ((uint64_t)begin_vaddr - (uint64_t)vaddr), signature_end, strlen(signature_end));
        if (end_vaddr != NULL)
        {
            paddr_t begin_paddr = page_addr + ((uint8_t *)begin_vaddr - (uint8_t *)vaddr);
            IMSG("found at %p:\n", (void *)begin_paddr);
            print_match(begin_vaddr);
            count++;
        }
    }

    free_page(mobj);
    return count;
}


uint16_t process_block(paddr_t block_base_addr, uint8_t level, char *signature_begin, char *signature_end)
{
    uint16_t count = 0;
    uint64_t block_addr = block_base_addr;
    while ((block_addr & BLOCK_ADRESS_MASKS[level]) == block_base_addr)
    {
        count += process_page(block_addr, signature_begin, signature_end);
        block_addr += PAGE_SIZE;
    }
    return count;
}


uint16_t process_translation_level(paddr_t level_base_addr, uint8_t level, char *signature_begin, char *signature_end)
{
    struct mobj *mobj = load_page(level_base_addr);
    if (!mobj)
        return 0;

    uint64_t *vaddr = mobj_get_va(mobj, 0);

    uint16_t count = 0;
    for(unsigned int i = 0; i < PAGE_SIZE / sizeof(uint64_t); i++)
    {
        uint64_t value = *(vaddr + i);

        if (!(value & 0x1))
            continue;

        if (value & 0x2)
        {
            // On level 3, the addresses are single pages
            if (level == PAGE_TRANSLATION_LEVEL)
            {
                uint64_t page_addr = value & PAGE_ADDRESS_MASK;
                uint16_t page_count = process_page(page_addr, signature_begin, signature_end);
                count += page_count;
            }
            // On all other levels, addresses with bit 1 set are addresses of further translation tables
            else
            {
                if (level >= MAX_TRANSLATION_LEVEL)
                    continue;

                // Bits[47:12] are bits[47:12] of the address of the required next-level table
                // Bits[11:0] of the table address are zero.
                uint64_t next_table_addr = value & TABLE_ADDRESS_MASK;
                count += process_translation_level(next_table_addr, level + 1, signature_begin, signature_end);
            }
        }
        else
        {
            // On level 1 and 2, the addresses are blocks
            if (level < MIN_BLOCK_TRANSLATION_LEVEL || level > MAX_BLOCK_TRANSLATION_LEVEL)
                continue;

            uint64_t block_addr = value & BLOCK_ADRESS_MASKS[level];
            uint16_t block_count = process_block(block_addr, level, signature_begin, signature_end);
            count += block_count;
        }
    }

    free_page(mobj);
    return count;
}


uint16_t signature_search(paddr_t swapper_pg_dir_addr, char *signature_begin, char *signature_end)
{
    return process_translation_level(swapper_pg_dir_addr, 0, signature_begin, signature_end);
}


paddr_t find_swapper_pg_dir(paddr_t swapper_pg_dir_upper_bound_addr)
{
    // swapper_pg_dir_upper_bound_addr is assumed to be page-aligned
    for (paddr_t page = swapper_pg_dir_upper_bound_addr; page > 0; page -= PAGE_SIZE)
    {
        struct mobj *mobj = load_page(page);
        if (!mobj)
            continue;
        void *vaddr = mobj_get_va(mobj, 0);
        bool empty = is_empty_page(vaddr);
        free_page(mobj);
        if (!empty)
            return page;
    }
    return ERROR_ADDR;
}


TEE_Result memory_carving(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    char *signature_begin = params[0].memref.buffer;
    char *signature_end = params[1].memref.buffer;

    paddr_t uefi_header_addr = find_kernel_entrypoint();
    IMSG("uefi header address: %p\n", (void *)uefi_header_addr);
    if (uefi_header_addr == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    paddr_t stext_addr = find_stext_addr(uefi_header_addr);
    IMSG("stext address: %p\n", (void *)stext_addr);
    if (stext_addr == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    // stext is aligned (ALIGN(SEGMENT_ALIGN))
    // swapper_pg_dir is located at a lower address, assume stext - PAGE_SIZE as upper bound
    // and skip empty pages
    paddr_t swapper_pg_dir_upper_bound_addr = stext_addr - PAGE_SIZE;
    IMSG("swapper_pg_dir upper bound: %p\n", (void *)swapper_pg_dir_upper_bound_addr);
    if (swapper_pg_dir_upper_bound_addr == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    paddr_t swapper_pg_dir_addr = find_swapper_pg_dir(swapper_pg_dir_upper_bound_addr);
    IMSG("swapper_pg_dir address: %p\n", (void *)swapper_pg_dir_addr);
    if (swapper_pg_dir_addr == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    uint16_t num_findings = signature_search(swapper_pg_dir_addr, signature_begin, signature_end);
    IMSG("found %d matches\n", num_findings);

    return TEE_SUCCESS;
}
