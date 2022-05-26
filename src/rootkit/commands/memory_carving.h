#ifndef ROOTKIT_COMMANDS_MEMORY_CARVING_H
#define ROOTKIT_COMMANDS_MEMORY_CARVING_H

#include <tee_api.h>

TEE_Result memory_carving(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif
