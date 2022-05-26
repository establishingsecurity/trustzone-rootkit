#ifndef ROOTKIT_COMMANDS_PROCESS_STARVATION_H
#define ROOTKIT_COMMANDS_PROCESS_STARVATION_H

#include <tee_api.h>


TEE_Result change_task_state(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif
