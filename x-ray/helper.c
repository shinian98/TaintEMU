#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "exec/cpu_ldst.h"
#include "exec/tb-flush.h"
#include "sysemu/cpus.h"
#include "hw/core/cpu.h"
#include "sysemu/x-ray.h"
#include "x-ray-internal.h"
#include "json.h"
#include "exec/helper-proto.h"
#include "tcg/tcg-taint.h"

void HELPER (aarch64_update_task) (CPUArchState *env) {
    #ifdef TARGET_AARCH64

    #endif
}

void HELPER (aarch64_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_AARCH64
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->xregs[1];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // if (ts != NULL) {
    //     cpu->current = *ts;
    // }
    #endif
}

void HELPER (amd64_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_X86_64
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->regs[6];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (armhf_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_ARM
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->regs[1];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (i386_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_I386
    target_ulong edx = env->regs[2];
    target_ulong next_ts_addr = edx;
    TVM_task_struct *ts;
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (m68k_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_M68K
    target_ulong a1 = env->aregs[1];
    target_ulong next_ts_addr = a1;
    TVM_task_struct *ts;
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (mips64_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_MIPS64
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->active_tc.gpr[5];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (ppc_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_PPC
    #ifdef TARGET_PPC64
    #else
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->gpr[4];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
    #endif
}

void HELPER (ppc64_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_PPC64
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->gpr[4];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (riscv64_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_RISCV64
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->gpr[11];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (s390x_update_current_task) (CPUArchState *env) {
    #ifdef TARGET_S390X
    target_ulong next_ts_addr;
    TVM_task_struct *ts;
    next_ts_addr = env->regs[3];
    CPUState* cpu = env_cpu (env);
    ts = x_ray_update_current_task (cpu, next_ts_addr);
    // // printf ("X-Ray: currently running: [%d]%s\n", ts->pid, ts->comm);
    #endif
}

void HELPER (check_pc) (CPUArchState *env) {
    #ifdef TARGET_X86_64
    CPUArchState *shadow_env;
    shadow_env = te_get_shadow_env (env);
    if (shadow_env->eip != 0) {
        printf ("Tainted PC Detected. Aborting...\n");
        exit (0);
    }
    #endif
}

void HELPER (x_ray_insert_hook) (CPUArchState *env, uint64_t fn_addr) {
    x_ray_hook_cb (env, fn_addr);
}