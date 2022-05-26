#include "common.h"
#include "../linux.h"
#include "../utils.h"

#include <ctype.h>

/*
0x40080000:  91005a4d  add      x13, x18, #0x16
 */
void *find_uefi_header(void *vaddr)
{
    uint16_t i = 0;
    uint32_t value = *((uint32_t *)vaddr + i);
    if(value == UEFI_HEADER_VALUE)
        return (uint32_t *)vaddr + i;
    return NULL;
}


paddr_t find_kernel_entrypoint(void)
{
    for (paddr_t page = NS_IMAGE_OFFSET; page < NS_IMAGE_OFFSET * 2; page += PAGE_SIZE)
    {
        struct mobj *mobj = load_page(page);
        if (!mobj)
            continue;
        uint64_t *vaddr = mobj_get_va(mobj, 0);
        void *uefi_header = find_uefi_header(vaddr);
        free_page(mobj);
        if (uefi_header)
        {
            paddr_t uefi_header_offset = (uint8_t *)uefi_header - (uint8_t *)vaddr;
            paddr_t uefi_header_pa = page + uefi_header_offset;
            return uefi_header_pa;
        }
    }
    return ERROR_ADDR;
}


paddr_t find_stext_addr(paddr_t uefi_header_addr)
{
    const uint8_t BRANCH_INSTRUCTION_OFFSET = 1;
    const uint8_t INSTRUCTION_SIZE = 4;
    const uint8_t INSTRUCTION_OFFSET = BRANCH_INSTRUCTION_OFFSET * INSTRUCTION_SIZE;

    struct mobj *mobj = load_page(uefi_header_addr);    // Assumes uefi header is page-aligned
    if (!mobj)
        return ERROR_ADDR;

    uint8_t *vaddr = mobj_get_va(mobj, 0);
    paddr_t stext_offset = extract_unconditional_branch_immediate(*((uint32_t *)(vaddr + INSTRUCTION_OFFSET)));
    free_page(mobj);

    paddr_t stext_addr = uefi_header_addr + INSTRUCTION_OFFSET + stext_offset;
    return stext_addr;
}


paddr_t find_init_task_name(paddr_t uefi_header_addr)
{
    for (paddr_t page = uefi_header_addr; page < NS_IMAGE_OFFSET * 2; page += PAGE_SIZE)
    {
        struct mobj *mobj = load_page(page);
        if (!mobj)
            continue;
        uint64_t *vaddr = mobj_get_va(mobj, 0);
        void *process_name = find(vaddr, PAGE_SIZE, 
                                  INIT_TASK_COMM, strlen(INIT_TASK_COMM) + 1);
        free_page(mobj);
        if (process_name)
        {
            paddr_t process_name_offset = (uint8_t *)process_name - (uint8_t *)vaddr;
            paddr_t process_name_pa = page + process_name_offset;
            return process_name_pa;
        }
    }
    return ERROR_ADDR;
}


paddr_t find_init_task_struct_signature(paddr_t init_task_name)
{
    const size_t NUM_SEARCHED_PAGES = 3;
    for (int i = 0; i < TASK_STRUCT_NUM_SIGNATURES; i++)
    {
        for (paddr_t page = init_task_name & ~PAGE_MASK, j = 0; j < NUM_SEARCHED_PAGES; page -= PAGE_SIZE, j++)
        {
            struct mobj *mobj = load_page(page);
            if (!mobj)
                return ERROR_ADDR;
            uint64_t *vaddr = mobj_get_va(mobj, 0);
            void *task_struct_signature = find_reverse_from(vaddr,
                                                            (j == 0) ? (init_task_name & PAGE_MASK) - 1 : PAGE_SIZE - 1,
                                                            TASK_STRUCT_SIGNATURE[i], sizeof(TASK_STRUCT_SIGNATURE[i]));
            free_page(mobj);
            if (task_struct_signature != NULL)
            {
                paddr_t task_struct_offset = (uint8_t *)task_struct_signature - (uint8_t *)vaddr - TASK_STRUCT_SIGNATURE_OFFSET;
                paddr_t task_struct_pa = page + task_struct_offset;
                return task_struct_pa;
            }
        }
    }

    return ERROR_ADDR;
}


paddr_t find_virtual_offset(paddr_t init_task_start)
{
    const size_t MIN_OCCURRENCES = 2;
    const size_t NUM_SEARCHED_PAGES = 3;
    bool first = true;
    paddr_t virtual_offset = NULL;
    size_t occurrences = 0;
    // fuzzy limit, as we do not know the exact size of the struct
    for (paddr_t page = init_task_start & ~PAGE_MASK; page < init_task_start + NUM_SEARCHED_PAGES * PAGE_SIZE; page += PAGE_SIZE)
    {
        struct mobj *mobj = load_page(page);
        if (!mobj)
            continue;
        uint64_t *vaddr = mobj_get_va(mobj, 0);
        void *parent = NULL;
        size_t offset = first ? (init_task_start & PAGE_OFFSET_MASK) : 0;

        while (parent == NULL && (parent = find_va_from_pa(vaddr, PAGE_SIZE, offset, init_task_start)))
        {
            if (!parent)
                break;

            occurrences = count_gw(vaddr, PAGE_SIZE, offset, *((uint64_t *)parent));      // TODO check also next page

            offset = ((uint64_t)parent & PAGE_OFFSET_MASK) + sizeof(uint64_t);
            if (occurrences < MIN_OCCURRENCES)
                parent = NULL;
        }

        if (parent)
            virtual_offset = *((uint64_t *)parent) - init_task_start;

        free_page(mobj);

        if (virtual_offset)
            return virtual_offset;
        
        // must be contained in the struct multiple times (currently 3)
        // currently we require that they are on the same page, thus MIN_OCCURRENCES is only 2
        first = false;
    }

    return ERROR_ADDR;
}


bool is_valid_comm(char *comm)
{
    for (int i = 0; i < TASK_COMM_LEN; i++)
    {
        if (i > 0 && comm[i] == '\0')       // comm is always zero-terminated (strlcpy)
            return true;
        else if (!isalnum(comm[i]))
            return false;
    }
    return false;
}


paddr_t get_multi_page_distance(paddr_t from, paddr_t to_page)
{
    paddr_t from_page = from & ~SMALL_PAGE_MASK;
    return (SMALL_PAGE_SIZE - (from & SMALL_PAGE_MASK)) + (to_page - from_page - SMALL_PAGE_SIZE);
}


paddr_t find_task_struct_tasks_offset(paddr_t init_task_start, paddr_t task_struct_name_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa)
{
    const size_t NUM_SEARCHED_PAGES = 3;
    bool first = true;
    paddr_t init_task_page = init_task_start & ~PAGE_MASK;
    for (paddr_t page = init_task_page; page < init_task_start + NUM_SEARCHED_PAGES * PAGE_SIZE; page += PAGE_SIZE)
    {
        struct mobj *mobj = load_page(page);
        if (!mobj)
            continue;

        uint64_t *vaddr = mobj_get_va(mobj, 0);
        paddr_t tasks = NULL;
        size_t offset = first ? (init_task_start & PAGE_OFFSET_MASK) : 0;
        paddr_t tasks_member_offset = 0;

        // Simply check everything that looks like a virtual address
        while (tasks == NULL && (tasks = find_va(vaddr, PAGE_SIZE, offset)))
        {
            if (!tasks)
                break;

            tasks_member_offset = tasks - (paddr_t)vaddr;
            if (page > init_task_page)
                tasks_member_offset += get_multi_page_distance(init_task_start, page);
            else
                tasks_member_offset -= init_task_start & PAGE_OFFSET_MASK;

            paddr_t list_addr = *((paddr_t *)tasks);
            paddr_t candidate_start_vaddr = list_addr - tasks_member_offset;
            paddr_t candidate_start = (*va_to_pa)(candidate_start_vaddr, virtual_address_offset);
            paddr_t candidate_name = candidate_start + task_struct_name_offset;
            offset = ((uint64_t)tasks & PAGE_OFFSET_MASK) + sizeof(uint64_t);

            // filter vas, because it should be a pa
            if (is_va(candidate_name))
            {
                tasks = NULL;
                continue;
            }

            // Validate candidate
            paddr_t candidate_name_page = candidate_name & ~PAGE_MASK;
            struct mobj *candidate_mobj = load_page(candidate_name_page);
            if (!candidate_mobj)
            {
                tasks = NULL;
                continue;
            }

            uint8_t *candidate_vaddr = mobj_get_va(candidate_mobj, 0);
            if (candidate_start == init_task_start || !is_valid_comm(((char *)candidate_vaddr + (task_struct_name_offset & PAGE_MASK))) || strcmp(((char *)candidate_vaddr + (task_struct_name_offset & PAGE_MASK)), "init") != 0)
            {
                tasks = NULL;
            }

            free_page(candidate_mobj);
            
            if (tasks)
            {
                // Check prev pointer
                paddr_t candidate_tasks_prev = candidate_start + tasks_member_offset + sizeof(uint64_t);
                paddr_t candidate_tasks_prev_page = candidate_tasks_prev & ~PAGE_MASK;
                struct mobj *candidate_tasks_prev_mobj = load_page(candidate_tasks_prev_page);
                if (!candidate_tasks_prev_mobj)
                {
                    tasks = NULL;
                    continue;
                }

                uint8_t *candidate_tasks_prev_vaddr = mobj_get_va(candidate_tasks_prev_mobj, 0);
                candidate_tasks_prev_vaddr += (tasks_member_offset + sizeof(uint64_t)) & PAGE_MASK;
                paddr_t candidate_tasks_prev_pa = (*va_to_pa)(*((uint64_t *)candidate_tasks_prev_vaddr), virtual_address_offset);
                if ((candidate_tasks_prev_pa - tasks_member_offset) != init_task_start)
                    tasks = NULL;

                free_page(candidate_tasks_prev_mobj);
            }
        }

        free_page(mobj);

        if (tasks && tasks_member_offset)
            return tasks_member_offset;

        first = false;
    }

    return ERROR_ADDR;
}


paddr_t find_task_struct_pid_offset(paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa)
{
    const size_t NUM_SEARCHED_PAGES = 3;
    paddr_t current_task;
    pid_t expected_pid;
    const size_t TASKS_TO_CHECK = 10;
    bool first;
    paddr_t offset = 0;
    // Assumes struct member is aligned
    for (paddr_t guessed_offset = 0; guessed_offset < NUM_SEARCHED_PAGES * PAGE_SIZE; guessed_offset += sizeof(pid_t))
    {
        expected_pid = 0;
        current_task = init_task_start;
        first = true;

        // Iterate over all tasks and search for an incrementing pattern
        while(first || (current_task != init_task_start && expected_pid < TASKS_TO_CHECK))
        {
            first = false;

            paddr_t current_task_page = current_task & ~PAGE_MASK;

            paddr_t pid_page = (current_task + guessed_offset) & ~PAGE_MASK;
            struct mobj *pid_mobj = load_page(pid_page);
            if (!pid_mobj)
                break;

            uint8_t *pid_page_vaddr = mobj_get_va(pid_mobj, 0);
            pid_t *pid_vaddr = (pid_t *)(pid_page_vaddr + guessed_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (pid_page - current_task_page - PAGE_SIZE));
            pid_t task_pid = *pid_vaddr;
            free_page(pid_mobj);

            if (task_pid != expected_pid)
            {
                offset = 0;
                break;
            }

            expected_pid++;
            offset = guessed_offset;

            paddr_t tasks_page = (current_task + task_struct_tasks_offset) & ~PAGE_MASK;
            struct mobj *tasks_mobj = load_page(tasks_page);
            if (!tasks_mobj)
                break;

            uint8_t *tasks_page_vaddr = mobj_get_va(tasks_mobj, 0);
            uint8_t *tasks_vaddr = tasks_page_vaddr + task_struct_tasks_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (tasks_page - current_task_page - PAGE_SIZE);
            current_task = (*va_to_pa)(*((uint64_t *)(tasks_vaddr)) - task_struct_tasks_offset, virtual_address_offset);
            free_page(tasks_mobj);
        }
        if (offset)
            return offset;
    }
    return ERROR_ADDR;
}
