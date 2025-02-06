#include "qemu/osdep.h"

#include "exec/exec-all.h"
#include "tcg/tcg-taint.h"
#include "sysemu/x-ray.h"

void
taint_write_notify (uint64_t addr, uint64_t taint, uint64_t val,CPUArchState *env) {
    /* Write Your Code Here*/
    // printf ("write notify\n");

    TVM_task_struct* ts;
    ts = x_ray_get_current_task (env_cpu(env));
    #ifdef TARGET_AARCH64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tWrite('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tWrite('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_X86_64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tWrite('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tWrite('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_I386
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tWrite('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tWrite('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_MIPS64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tWrite('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->active_tc.PC), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tWrite('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->active_tc.PC), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_PPC
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tWrite('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->nip), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tWrite('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->nip), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_RISCV64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tWrite('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tWrite('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_S390X
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tWrite('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->psw.addr), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tWrite('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->psw.addr), ts->pid, ts->comm);
    }
    #endif
    
}

void
taint_read_notify (uint64_t addr, uint64_t taint, uint64_t val, CPUArchState *env) {
    /* Write Your Code Here*/
    // printf ("read notify\n");
    TVM_task_struct* ts;
    ts = x_ray_get_current_task (env_cpu(env));
    #ifdef TARGET_AARCH64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tRead('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tRead('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_X86_64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tRead('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tRead('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_I386
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tRead('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tRead('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->eip), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_MIPS64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tRead('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->active_tc.PC), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tRead('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->active_tc.PC), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_PPC
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tRead('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->nip), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tRead('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->nip), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_RISCV64
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tRead('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tRead('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->pc), ts->pid, ts->comm);
    }
    #endif
    #ifdef TARGET_S390X
    if (isgraph ((char)val)) {
        printf ("Taint(0x%lX)\tRead('%c')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, (char)val, addr, x_ray_get_kernel_func_name (env->psw.addr), ts->pid, ts->comm);
    } else {
        printf ("Taint(0x%lX)\tRead('\\x%lx')@[0x%lX]\tExecuting:%s ([%d]%s)\n", taint, val, addr, x_ray_get_kernel_func_name (env->psw.addr), ts->pid, ts->comm);
    }
    #endif
}

void
taint_exec_notify (uint64_t addr, uint64_t taint) {
    /* Write Your Code Here*/
    // printf ("exec notify\n");
}