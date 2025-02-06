#include "qemu/osdep.h"
#include "exec/cpu_ldst.h"
#include "sysemu/x-ray.h"
#include "x-ray-internal.h"
#include "tcg/tcg-taint.h"

static void taint_usb_serial (CPUArchState* env, uint64_t addr) {
    uint32_t cnt;
    target_ulong urb_ptr;
    target_ulong data_ptr;
    char buf [1024];
    int i;
    char c;
    #ifdef TARGET_AARCH64
    #define URB_ACTUAL_LENGTH 0x84
    #define URB_TRANSFER_BUFFER 0x60
    bzero (buf, 1024);
    urb_ptr = env->xregs[0];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldq_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        buf[i] = c;
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%lX]\n", cnt, data_ptr);
    #elif defined (TARGET_ARM)
    #define URB_ACTUAL_LENGTH 0x60
    #define URB_TRANSFER_BUFFER 0x40

    #elif defined (TARGET_X86_64)
    #define URB_ACTUAL_LENGTH 0x84
    #define URB_TRANSFER_BUFFER 0x60
    bzero (buf, 1024);
    urb_ptr = env->regs[7];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldq_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        buf[i] = c;
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%lX]\n", cnt, data_ptr);


    #elif defined (TARGET_I386)
    #define URB_ACTUAL_LENGTH 0x58
    #define URB_TRANSFER_BUFFER 0x40
    bzero (buf, 1024);
    // target_ulong ebp = env->regs[5];
    // urb_ptr = cpu_ldl_data(env, ebp-4);
    urb_ptr = env->regs[0];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldl_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        buf[i] = c;
        printf ("ftdi_process_read_urb: input char: %c\n", c);
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%lX]\n", cnt, data_ptr);


    #elif defined (TARGET_M68K)
    #define URB_ACTUAL_LENGTH 0x58
    #define URB_TRANSFER_BUFFER 0x40


    #elif defined (TARGET_MIPS64)
    #define URB_ACTUAL_LENGTH 0x84
    #define URB_TRANSFER_BUFFER 0x60
    bzero (buf, 1024);
    urb_ptr = env->active_tc.gpr[4];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldq_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        buf[i] = c;
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%lX]\n", cnt, data_ptr);

    #elif defined (TARGET_PPC64)
    #define URB_ACTUAL_LENGTH 0x84
    #define URB_TRANSFER_BUFFER 0x60
    bzero (buf, 1024);
    urb_ptr = env->gpr[3];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldq_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        buf[i] = c;
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%lX]\n", cnt, data_ptr);

    #elif defined (TARGET_PPC)
    #define URB_ACTUAL_LENGTH 0x58
    #define URB_TRANSFER_BUFFER 0x40
    bzero (buf, 1024);
    urb_ptr = env->gpr[3];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldl_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        buf[i] = c;
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%X]\n", cnt, data_ptr);

    #elif defined (TARGET_RISCV64)
    #define URB_ACTUAL_LENGTH 0x84
    #define URB_TRANSFER_BUFFER 0x60
    bzero (buf, 1024);
    urb_ptr = env->gpr[10];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldq_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        buf[i] = c;
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%lX]\n", cnt, data_ptr);

    #elif defined (TARGET_S390X)
    #define URB_ACTUAL_LENGTH 0x84
    #define URB_TRANSFER_BUFFER 0x60
    bzero (buf, 1024);
    urb_ptr = env->regs[2];
    cnt = cpu_ldl_data(env, urb_ptr + URB_ACTUAL_LENGTH);
    data_ptr = cpu_ldq_data(env, urb_ptr + URB_TRANSFER_BUFFER);
    for (i = 0; i < cnt; i++) {
        if (i >= 1024) break;
        c = cpu_ldub_data (env, data_ptr + i);
        cpu_stb_taint (env, data_ptr + i, 0xFF);
        printf ("ftdi_process_read_urb: input char: %c\n", c);
        buf[i] = c;
    }
    printf ("ftdi_process_read_urb: tainting %d bytes data to [0x%lX]\n", cnt, data_ptr);

    #else
    /* Do nothing */
    #endif
}

#if 1

#define ADDR_RDS_write_to_mem 0x400f7e

static void taint_full_nelson (CPUArchState* env, uint64_t addr) {

}


static void taint_half_nelson (CPUArchState* env, uint64_t addr) {

}

static void taint_rds (CPUArchState* env, uint64_t addr) {
    #ifdef TARGET_X86_64
    CPUArchState* shadow_env;
    TVM_task_struct *ts = x_ray_get_current_task (env_cpu(env));
    if (addr == ADDR_RDS_write_to_mem && strstr (ts->comm, "rds64")) {
        shadow_env = te_get_shadow_env (env);
        shadow_env->regs[6] = 0xFFFFFFFFFFFFFFFF;
        printf ("X-Ray : got write_to_mem. tainting *SHADOW* RSI\n");
    }
    #endif
}

static void taint_ptrace_kmod2 (CPUArchState* env, uint64_t addr) {

}

static void taint_memodipper (CPUArchState* env, uint64_t addr) {

}

static void taint_perf_swevent (CPUArchState* env, uint64_t addr) {

}

static void taint_timeoutpwn (CPUArchState* env, uint64_t addr) {

}

#define ADDR_NASM_prepreproc_SOURCE 0x41A51D
#define ADDR_NASM_tokenize_SINK 0x411DE6

static void taint_nasm_source (CPUArchState* env, uint64_t addr) {
    #ifdef TARGET_X86_64
    target_ulong r14;
    target_ulong ptr;
    char c;
    int i;
    TVM_task_struct *ts = x_ray_get_current_task (env_cpu(env));
    if (addr == ADDR_NASM_prepreproc_SOURCE && strstr (ts->comm, "nasm")) {
        printf ("X-Ray : got prepreproc, tainting *r14\n");
        i = 0;
        r14 = env->regs[14]; // R14
        ptr = r14;
        c = cpu_ldub_data (env, ptr);
        while (c != 0) {
            cpu_stb_taint (env, ptr + i, 0xFF);
            c = cpu_ldub_data (env, ptr + i);
            i++;
        }
    }
    #endif
}

static void check_nasm_sink (CPUArchState* env, uint64_t addr) {
    #ifdef TARGET_X86_64
    target_ulong rdi;
    char t;
    TVM_task_struct *ts = x_ray_get_current_task (env_cpu(env));
    if (addr == ADDR_NASM_tokenize_SINK && strstr (ts->comm, "nasm")) {
        printf ("X-Ray : got tokenize, checking *rdi\n");
        rdi = env->regs[7];
        t = cpu_ldub_taint (env, rdi);
        if (t != 0) {
            printf ("Tainted data reached sink point.\n");
        }
    }
    #endif
}

#endif


void hook_register (void) {
    x_ray_add_kernel_hook ("ftdi_process_read_urb", taint_usb_serial);
    x_ray_add_process_hook (ADDR_RDS_write_to_mem, taint_rds);
    x_ray_add_process_hook (ADDR_NASM_prepreproc_SOURCE, taint_nasm_source);
    x_ray_add_process_hook (ADDR_NASM_tokenize_SINK, check_nasm_sink);
}