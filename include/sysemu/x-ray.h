#ifndef X_RAY_H
#define X_RAY_H


#define TASK_COMM_LEN 128
#define MAX_SYMBOL_LEN 64
#define MAX_PATH_LEN 256
#define SYMTAB_START_LEN 4096

typedef struct SymElem {
    uint64_t addr;
    char type;
    char sym[MAX_SYMBOL_LEN];
} SymElem;

typedef struct SymTab {
    SymElem *syms;
    size_t max_len;
    size_t len;
} SymTab;

typedef struct TVM_mm_struct {
    uint64_t code_start;
    uint64_t code_end;
} TVM_mm_struct;

typedef struct TVM_task_struct {
    uint64_t addr; // task_struct virtual address
    char comm[TASK_COMM_LEN];
    uint32_t pid;
    uint32_t tgid;
    TVM_mm_struct mm;
    uint64_t next_task;
    struct TVM_task_struct *next;
} TVM_task_struct;

enum TVMInfoStat {
    TVM_INFO_STAT_BIT_os_type = 0x1,
    TVM_INFO_STAT_BIT_sysmap_path = 0x2,
    TVM_INFO_STAT_BIT_symbol_switch = 0x4,
    TVM_INFO_STAT_BIT_linux_name = 0x8,
    TVM_INFO_STAT_BIT_linux_tasks = 0x10,
    TVM_INFO_STAT_BIT_linux_mm = 0x20,
    TVM_INFO_STAT_BIT_linux_pid = 0x40,
    TVM_INFO_STAT_BIT_linux_tgid = 0x80,
    TVM_INFO_STAT_BIT_linux_pgd = 0x100,
    TVM_INFO_STAT_BIT_ALL = 0x1FF
};

typedef struct TVMInfo {
    enum {
        TVM_OS_UNKNOWN = 0,
        TVM_OS_LINUX
    } os_type;
    char sysmap_path [MAX_PATH_LEN];
    char symbol_switch [MAX_SYMBOL_LEN]; // the name of switch_to
    uint64_t linux_name;
    uint64_t linux_tasks;
    uint64_t linux_mm;
    uint64_t linux_pid;
    uint64_t linux_tgid;
    uint64_t linux_pgd;
    int stat;
} TVMInfo;

typedef struct TVMState{
    TVMInfo info;
    SymTab sym_tab;
    uint64_t switch_addr;
    uint64_t init_task_addr;
    TVM_task_struct init_task;
    int task_num;
    enum {
        TVM_STATE_UNKNOWN = 0,
        TVM_STATE_INFO_LOADED,
        TVM_STATE_SEARCHING,
        TVM_STATE_XRAY_READY
    } stat;
} TVMState;


int x_ray_init (void);

int x_ray_reset (void);

int x_ray_tvm_setup (const char *config);

bool x_ray_need_flush_tb (void);

void x_ray_flush_tb (CPUState *cpu);

// void x_ray_update_tvm (CPUState *cpu);

const char * x_ray_get_kernel_func_name (uint64_t addr);

TVMState * x_ray_get_tvm_state (void);

TVMState * x_ray_update_tvm_state (CPUState *cpu, uint64_t valid_ts_addr);

TVM_task_struct* x_ray_update_current_task (CPUState *cpu, uint64_t addr);

TVM_task_struct* x_ray_get_current_task (CPUState *cpu);

bool x_ray_need_insert_hook (CPUState *cpu, uint64_t ptr);

bool x_ray_is_switch_addr (uint64_t addr);

void x_ray_hook_cb (CPUArchState *env, uint64_t fn_addr);

#endif