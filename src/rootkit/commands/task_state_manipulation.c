#include "task_state_manipulation.h"
#include "common.h"
#include "../utils.h"

#include <types_ext.h>


bool change_task_struct_state(pid_t target_pid, paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_pid_offset,
                              paddr_t task_struct_state_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa, long new_state);
paddr_t find_task_struct_state_offset(paddr_t init_task_start, paddr_t task_struct_tasks_offset,
                                      paddr_t virtual_address_offset, address_translation_function va_to_pa);


paddr_t find_task_struct_state_offset(paddr_t init_task_start, paddr_t task_struct_tasks_offset,
                                      paddr_t virtual_address_offset, address_translation_function va_to_pa)
{
    const size_t NUM_SEARCHED_PAGES = 3;

    paddr_t current_task;
    uint32_t counter[NUM_COUNTED_STATES];

    // Assumes struct member is aligned
    for (paddr_t guessed_offset = 0; guessed_offset < NUM_SEARCHED_PAGES * PAGE_SIZE; guessed_offset += sizeof(uint64_t))
    {
        current_task = init_task_start;
        bool first = true;

        reset_task_state_counter(counter);

        while(first || (current_task != init_task_start))
        {
            first = false;

            paddr_t current_task_page = current_task & ~PAGE_MASK;

            paddr_t state_page = (current_task + guessed_offset) & ~PAGE_MASK;
            struct mobj *state_mobj = load_page(state_page);
            if (!state_mobj)
                break;

            uint8_t *state_page_vaddr = mobj_get_va(state_mobj, 0);
            unsigned int *state_vaddr = state_page_vaddr + guessed_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (state_page - current_task_page - PAGE_SIZE);
            uint64_t state = *state_vaddr;
            free_page(state_mobj);

            count_task_state(state, counter);

            paddr_t tasks_page = (current_task + task_struct_tasks_offset) & ~PAGE_MASK;
            struct mobj *tasks_mobj = load_page(tasks_page);
            if (!tasks_mobj)
                break;

            uint8_t *tasks_page_vaddr = mobj_get_va(tasks_mobj, 0);
            uint8_t *tasks_vaddr = tasks_page_vaddr + task_struct_tasks_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (tasks_page - current_task_page - PAGE_SIZE);
            current_task = (*va_to_pa)(*((uint64_t *)(tasks_vaddr)) - task_struct_tasks_offset, virtual_address_offset);
            free_page(tasks_mobj);
        }

        if (task_state_count_valid(counter))
            return guessed_offset;
    }

    return ERROR_ADDR;
}


bool change_task_struct_state(pid_t target_pid, paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_pid_offset,
                              paddr_t task_struct_state_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa, long new_state)
{
    paddr_t current_task = init_task_start;
    bool first = true;
    while(first || current_task != init_task_start)
    {
        paddr_t current_task_page = current_task & ~PAGE_MASK;

        paddr_t pid_page = (current_task + task_struct_pid_offset) & ~PAGE_MASK;
        struct mobj *pid_mobj = load_page(pid_page);
        if (!pid_mobj)
            return false;

        uint8_t *pid_page_vaddr = mobj_get_va(pid_mobj, 0);
        uint8_t *pid_vaddr = pid_page_vaddr + task_struct_pid_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (pid_page - current_task_page - PAGE_SIZE);
        bool is_target_task = *((pid_t *) pid_vaddr) == target_pid;
        free_page(pid_mobj);

        if (is_target_task)
        {
            paddr_t state_page = (current_task + task_struct_state_offset) & ~PAGE_MASK;
            struct mobj *state_mobj = load_page(state_page);
            if (!state_mobj)
                return false;

            uint8_t *state_page_vaddr = mobj_get_va(state_mobj, 0);
            uint8_t *state_vaddr = state_page_vaddr + task_struct_state_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (state_page - current_task_page - PAGE_SIZE);
            *((uint64_t *)state_vaddr) = new_state;
            free_page(state_mobj);
            return true;
        }

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


TEE_Result change_task_state(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_VALUE_INPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    pid_t target_pid = params[0].value.a;
    long new_state = params[1].value.a;

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

    paddr_t task_struct_state_offset = find_task_struct_state_offset(init_task_start, task_struct_tasks_offset, virtual_address_offset, va_to_pa);
    IMSG("task_struct.state offsets: %lx\n", task_struct_state_offset);
    if (task_struct_state_offset == ERROR_ADDR)
        return TEE_ERROR_GENERIC;

    IMSG("tasks:\n");
    print_tasks(init_task_start, task_struct_tasks_offset, task_struct_name_offset, task_struct_pid_offset, virtual_address_offset, va_to_pa);

    IMSG("changing state of pid %d\n", target_pid);
    bool state_change_successful = change_task_struct_state(target_pid, init_task_start, task_struct_tasks_offset,
                                                            task_struct_pid_offset, task_struct_state_offset,
                                                            virtual_address_offset, va_to_pa, new_state);
    if (state_change_successful)
    {
        IMSG("changed state\n");
        return TEE_SUCCESS;
    }
    else
    {
        IMSG("could not change state\n");
        return TEE_ERROR_GENERIC;
    }
}
