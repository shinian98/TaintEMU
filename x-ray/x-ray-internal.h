#ifndef X_RAY_INTERNAL_H
#define X_RAY_INTERNAL_H

#define MAX_HOOK_NUM 1024

typedef void (*xray_callback_t) (CPUArchState *env, uint64_t addr);

typedef struct Hook {
    enum {
        HOOK_KERNEL = 0,
        HOOK_PROCESS
    } type;
    char comm [TASK_COMM_LEN]; // process name or kernel function name
    uint64_t addr;
    xray_callback_t cb;
    bool active;
} Hook;

typedef struct HookList {
    Hook hooks[MAX_HOOK_NUM];
    size_t num;
} HookList;

typedef struct XRayState {
    TVMState tvm;

    HookList hk;

    bool need_flush_tb;
    
    QemuSpin x_ray_lk;

    QemuSpin tvm_lk;

    QemuSpin qmp_lk;

    enum {
        XRAY_WAITTING = 0,
        XRAY_READY,
    } stat;
} XRayState;

int x_ray_add_kernel_hook (const char *name, xray_callback_t cb);

int x_ray_add_process_hook (uint64_t ptr, xray_callback_t cb);

void hook_register (void);

#endif