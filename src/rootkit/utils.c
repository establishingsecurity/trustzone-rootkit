#include "utils.h"


// Arm Architecture Reference Manual: C6.2.26
// https://github.com/aquynh/capstone/blob/0dc008920f8345274b4a596f9a1bbe703d083123/arch/AArch64/AArch64Disassembler.c#L1591-L1605
uint32_t extract_unconditional_branch_immediate(uint32_t instruction)
{
    uint32_t imm = (instruction & ((1 << 26) - 1));
    if (imm & (1 << (26 - 1)))
        imm |= ~((1LL << 26) - 1);
    return imm * 4;
} 


void *find(void const *haystack, size_t haystack_size, void const *needle, size_t needle_size)
{
    for (size_t i = 0; (i + needle_size - 1) < haystack_size; i++)
    {
        bool found = true;
        for (size_t j = 0; j < needle_size && found; j++)
        {
            if (((uint8_t *)haystack)[i + j] != ((uint8_t *)needle)[j])
                found = false;
        }
        if (found)
            return ((uint8_t *)haystack) + i;
    }
    return NULL;
}


void *find_va_from_pa(void const *haystack, size_t haystack_size, size_t offset, paddr_t pa)
{
    for (int i = offset; (i + sizeof(uint64_t) - 1) < haystack_size; i += sizeof(uint64_t))
    {
        uint64_t value = *((uint64_t *)((uint8_t *)haystack + i));
        if (is_va(value))
        {
            if ((value & PAGE_OFFSET_MASK) == (pa & PAGE_OFFSET_MASK))
                return (uint8_t *)haystack + i;
        }
    }
    return NULL;
}


void *find_va(void const *haystack, size_t haystack_size, size_t offset)
{
    for (int i = offset; (i + sizeof(uint64_t) - 1) < haystack_size; i += sizeof(uint64_t))
    {
        uint64_t value = *((uint64_t *)((uint8_t *)haystack + i));
        if (is_va(value))
            return (uint8_t *)haystack + i;
    }
    return NULL;
}


void *find_reverse_from(void const *haystack, size_t offset, void const *needle, size_t needle_size)
{
    for (int i = offset - needle_size + 1; i >= 0; i--)
    {
        bool found = true;
        for (size_t j = 0; j < needle_size && found; j++)
        {
            if (((uint8_t *)haystack)[i + j] != ((uint8_t *)needle)[j])
                found = false;
        }
        if (found)
            return ((uint8_t *)haystack) + i;
    }
    return NULL;
}


size_t count_gw(void *haystack, size_t haystack_size, size_t offset, uint64_t needle)
{
    size_t c = 0;
    for (size_t i = offset / sizeof(needle); i < haystack_size / sizeof(needle); i++)
    {
        if (((uint64_t *)haystack)[i] == needle)
            c++;
    }
    return c;
}


size_t find_gw_offsets(void const *haystack, size_t haystack_size, size_t offset, uint64_t needle, paddr_t offsets[], size_t max_offsets)
{
    size_t c = 0;
    for (size_t i = offset / sizeof(needle); i < haystack_size / sizeof(needle) && c < max_offsets; i++)
    {
        if (((uint64_t *)haystack)[i] == needle)
        {
            offsets[c++] = i * sizeof(needle);
        }
    }
    return c;
}


size_t count_values(uint64_t *array, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        if (array[i] == 0)
            return i;
    }
    return size;
}


// Return true if value was added, otherwise false
bool add_unique_value(uint64_t *array, size_t size, uint64_t value)
{
    for (size_t i = 0; i < size; i++)
    {
        if (array[i] == value)
            return false;
        if (array[i] == 0)
        {
            array[i] = value;
            return true;
        }
    }
    return false;
}


void reset_task_state_counter(uint32_t counter[NUM_COUNTED_STATES])
{
    memset(counter, 0, sizeof(uint32_t) * NUM_COUNTED_STATES);
}


void count_task_state(uint64_t state, uint32_t counter[NUM_COUNTED_STATES])
{
    for (int i = 0; i < NUM_COUNTED_STATES; i++)
    {
        if (STATE_MAPPING[i] == state)
        {
            counter[i]++;
            return;
        }
    }
}


bool task_state_count_valid(uint32_t counter[NUM_COUNTED_STATES])
{
    for (int i = 0; i < NUM_COUNTED_STATES; i++)
    {
        if (counter[i] < MIN_STATE_OCCURRENCES)
            return false;
    }
    return true;
}


void print_tasks(paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_name_offset, paddr_t task_struct_pid_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa)
{
    paddr_t current_task = init_task_start;
    bool first = true;
    while(first || current_task != init_task_start)
    {
        first = false;

        paddr_t current_task_page = current_task & ~PAGE_MASK;

        paddr_t pid_page = (current_task + task_struct_pid_offset) & ~PAGE_MASK;
        struct mobj *pid_mobj = load_page(pid_page);
        if (!pid_mobj)
            break;

        uint8_t *pid_page_vaddr = mobj_get_va(pid_mobj, 0);
        pid_t *pid_vaddr = (pid_t *)(pid_page_vaddr + task_struct_pid_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (pid_page - current_task_page - PAGE_SIZE));
        pid_t pid = *pid_vaddr;
        free_page(pid_mobj);

        paddr_t name_page = (current_task + task_struct_name_offset) & ~PAGE_MASK;
        struct mobj *name_mobj = load_page(name_page);
        if (!name_mobj)
            break;

        uint8_t *name_page_vaddr = mobj_get_va(name_mobj, 0);
        uint8_t *name_vaddr = name_page_vaddr + task_struct_name_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (name_page - current_task_page - PAGE_SIZE);
        IMSG("\t%p %d %s\n", (void *)current_task, pid, (char *)name_vaddr);
        free_page(name_mobj);

        paddr_t tasks_page = (current_task + task_struct_tasks_offset) & ~PAGE_MASK;
        struct mobj *tasks_mobj = load_page(tasks_page);
        if (!tasks_mobj)
            break;

        uint8_t *tasks_page_vaddr = mobj_get_va(tasks_mobj, 0);
        uint8_t *tasks_vaddr = tasks_page_vaddr + task_struct_tasks_offset - (PAGE_SIZE - (current_task & PAGE_MASK)) - (tasks_page - current_task_page - PAGE_SIZE);
        current_task = (*va_to_pa)(*((uint64_t *)(tasks_vaddr)) - task_struct_tasks_offset, virtual_address_offset);
        free_page(tasks_mobj);
    }
}
