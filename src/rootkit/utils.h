#ifndef ROOTKIT_UTILS_H
#define ROOTKIT_UTILS_H

#include "linux.h"
#include "memory.h"

uint32_t extract_unconditional_branch_immediate(uint32_t instruction); 
void *find(void const *haystack, size_t haystack_size, void const *needle, size_t needle_size);
void *find_va_from_pa(void const *haystack, size_t haystack_size, size_t offset, paddr_t pa);
void *find_va(void const *haystack, size_t haystack_size, size_t offset);
void *find_reverse_from(void const *haystack, size_t offset, void const *needle, size_t needle_size);
size_t count_gw(void *haystack, size_t haystack_size, size_t offset, uint64_t needle);
size_t find_gw_offsets(void const *haystack, size_t haystack_size, size_t offset, uint64_t needle, paddr_t offsets[], size_t max_offsets);
size_t count_values(uint64_t *array, size_t size);
// Return true if value was added, otherwise false
bool add_unique_value(uint64_t *array, size_t size, uint64_t value);
void reset_task_state_counter(uint32_t counter[NUM_COUNTED_STATES]);
void count_task_state(uint64_t state, uint32_t counter[NUM_COUNTED_STATES]);
bool task_state_count_valid(uint32_t counter[NUM_COUNTED_STATES]);
void print_tasks(paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t task_struct_name_offset,
                 paddr_t task_struct_pid_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa);

#endif
