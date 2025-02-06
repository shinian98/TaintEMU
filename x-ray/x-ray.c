#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "exec/cpu_ldst.h"
#include "exec/tb-flush.h"
#include "sysemu/cpus.h"
#include "hw/core/cpu.h"
#include "sysemu/x-ray.h"
#include "qapi/error.h"
#include "x-ray-internal.h"
#include "qapi/qapi-commands-misc.h"
#include "json.h"

XRayState xray;

int x_ray_init (void) {
    bzero (&xray, sizeof (xray));
    xray.stat = XRAY_READY;
    qemu_spin_init (&xray.x_ray_lk);
    qemu_spin_init (&xray.tvm_lk);
    qemu_spin_init (&xray.qmp_lk);
    hook_register ();
    return 0;
}

int x_ray_reset (void) {
    // need to free memory
    bzero (&xray, sizeof (xray));
    xray.stat = XRAY_READY;
    return 0;
}

static int sym_tab_init (SymTab *tab) {
    tab->max_len = SYMTAB_START_LEN;
    tab->syms = malloc (sizeof (SymElem) * tab->max_len);
    tab->len = 0;
    return 0;
}

static int sym_tab_increase (SymTab *tab) {
    tab->max_len *= 2;
    tab->syms = realloc (tab->syms ,sizeof (SymElem) * tab->max_len);
    // keep tab->len unchanged
    return 0;
}

static __attribute__ (( unused )) int sym_tab_free (SymTab* tab) {
    free (tab->syms);
    tab->max_len = 0;
    tab->len = 0;
    return 0;
}

static int sym_tab_add (SymTab *tab, SymElem *e) {
    if (tab->len >= tab->max_len - 1) {
        sym_tab_increase (tab);
    }
    tab->syms[tab->len].addr = e->addr;
    strcpy (tab->syms[tab->len].sym, e->sym);
    tab->syms[tab->len].type = e->type;
    tab->len++;
    return 0;
}

static int get_sysmap_elem (SymElem *buf, const char* line) {
    if (sscanf (line, "%lX %c %s", &buf->addr, &buf->type, buf->sym) != 3) {
        return -1;
    }
    return 0;
}

static TVM_task_struct * load_task_struct (CPUState *cpu, uint64_t addr) {
    TVMState *tvm;
    TVMInfo *info = NULL;
    TVM_task_struct *ts;
    abi_ptr ptr;
    abi_ptr next_tasks;
    CPUArchState *env;
    env = cpu_env (cpu);
    char buf[TASK_COMM_LEN];
    int i;
    char c;
    tvm = x_ray_get_tvm_state ();
    if (tvm->stat == TVM_STATE_XRAY_READY) {
        info = &(tvm->info);
        ts = (TVM_task_struct*) malloc (sizeof (TVM_task_struct));
        // addr
        ts->addr = (abi_ptr) addr;
        // comm 
        ptr = addr + info->linux_name;
        for (i = 0; i < TASK_COMM_LEN; i++) {
            if (i == TASK_COMM_LEN - 1) {
                buf[i] = 0;
                break;
            }
            c = cpu_ldub_data (env, ptr+i);
            buf[i] = c;
            if (c == 0)
                break;
        }
        memcpy (ts->comm, buf, sizeof (ts->comm));
        // pid;
        ptr = addr + info->linux_pid;
        ts->pid = cpu_ldl_data (env, ptr);
        // tgid
        ptr = addr + info->linux_tgid;
        ts->tgid = cpu_ldl_data (env, ptr);
        // next_task
        ptr = addr + info->linux_tasks;
        #if TARGET_LONG_SIZE == 4
        next_tasks = cpu_ldl_data (env, ptr);
        #elif TARGET_LONG_SIZE == 8
        next_tasks = cpu_ldq_data (env, ptr);
        #else
        #error TARGET_LONG_SIZE undefined
        #endif
        ts->next_task = next_tasks - info->linux_tasks;
        // load mm later...
        ts->next = NULL;
    } else {
        return NULL;
    }
    return ts;
}


static int setup_tvm (TVMState *tvm , FILE *sysmap) {
    SymElem elem;
    SymTab *sym_tab = &(tvm->sym_tab);
    char *line = NULL;
    size_t len;
    ssize_t nread;
    bool switch_addr_set = FALSE;
    sym_tab_init (sym_tab);
    while ((nread = getline(&line, &len, sysmap)) != -1) {
        if (get_sysmap_elem (&elem, line) == -1) {
            // printf ("x-ray error: sysmap parse error.\n");
            continue;
        }
        if (elem.type == 't' || elem.type == 'T') {
            sym_tab_add (sym_tab, &elem);
        }
        if (!strcmp (elem.sym , tvm->info.symbol_switch)) {
            printf ("swtich address is : 0x%lx\n", elem.addr);
            tvm->switch_addr = elem.addr;
            switch_addr_set = TRUE;
        }
        if (!strcmp (elem.sym , "init_task")) {
            tvm->init_task_addr = elem.addr;
        }
    }
    free (line);
    if (switch_addr_set) {
        tvm->stat = TVM_STATE_XRAY_READY;
    } else {
        printf ("x-ray waring: switch addr not set.\n");
    }
    return 0;
}

static int set_tvm_info (TVMInfo *info, struct json_string_s* name,
                    struct json_value_s* val) {
    int set = 0;
    struct json_string_s* str;
    struct json_number_s* num;
    if (!strcmp (name->string, "ostype")) {
        str = val->payload;
        if (!strcmp (str->string, "linux")) {
            info->os_type = TVM_OS_LINUX;
        } else {
            info->os_type = TVM_OS_UNKNOWN;
        }
        info->stat |= TVM_INFO_STAT_BIT_os_type;
        set = 1;
        printf ("ostype:%s\n",str->string);
    }
    if (!strcmp (name->string, "sysmap")) {
        str = val->payload;
        if (str->string_size >= MAX_PATH_LEN) {
            printf ("x-ray error: sysmap path is too long.\n");
        } else {
            strncpy (info->sysmap_path, str->string, str->string_size);
            info->stat |= TVM_INFO_STAT_BIT_sysmap_path;
            set = 1;
        }
        printf ("sysmap_path:%s\n",str->string);
    }
    if (!strcmp (name->string, "switch")) {
        str = val->payload;
        if (str->string_size >= MAX_SYMBOL_LEN) {
            printf ("x-ray error: switch symbol is too long.\n");
        } else {
            strncpy (info->symbol_switch, str->string, str->string_size);
            info->stat |= TVM_INFO_STAT_BIT_symbol_switch;
            set = 1;
        }
        printf ("switch:%s\n",str->string);
    }
    if (!strcmp (name->string, "linux_name")) {
        num = val->payload;
        info->linux_name = atoi (num->number);
        info->stat |= TVM_INFO_STAT_BIT_linux_name;
        set = 1;
        printf ("linux_name:0x%x\n",atoi (num->number));
    }
    if (!strcmp (name->string, "linux_tasks")) {
        num = val->payload;
        info->linux_tasks = atoi (num->number);
        info->stat |= TVM_INFO_STAT_BIT_linux_tasks;
        set = 1;
        printf ("linux_tasks:0x%x\n",atoi (num->number));
    }
    if (!strcmp (name->string, "linux_mm")) {
        num = val->payload;
        info->linux_mm = atoi (num->number);
        info->stat |= TVM_INFO_STAT_BIT_linux_mm;
        set = 1;
        printf ("linux_mm:0x%x\n",atoi (num->number));
    }
    if (!strcmp (name->string, "linux_pid")) {
        num = val->payload;
        info->linux_pid = atoi (num->number);
        info->stat |= TVM_INFO_STAT_BIT_linux_pid;
        set = 1;
        printf ("linux_pid:0x%x\n",atoi (num->number));
    }
    if (!strcmp (name->string, "linux_tgid")) {
        num = val->payload;
        info->linux_tgid = atoi (num->number);
        info->stat |= TVM_INFO_STAT_BIT_linux_tgid;
        set = 1;
        printf ("linux_tgid:0x%x\n",atoi (num->number));
    }
    if (!strcmp (name->string, "linux_pgd")) {
        num = val->payload;
        info->linux_pgd = atoi (num->number);
        info->stat |= TVM_INFO_STAT_BIT_linux_pgd;
        set = 1;
        printf ("linux_pgd:0x%x\n",atoi (num->number));
    }
    return set;
}


int x_ray_tvm_setup (const char *config) {
    TVMState *tvm = &(xray.tvm);
    TVMInfo *info = &(tvm->info);
    FILE *cfg;
    FILE *sysmap;
    #define CFG_BUFSZ 1024
    char cfg_buf[CFG_BUFSZ];
    size_t cfg_filesz;
    cfg = fopen (config, "r");
    if (!cfg)  {
        printf ("x-ray error: unable to open config file.\n");
        return -1;
    }
    fseek (cfg, 0, SEEK_END);
    cfg_filesz = ftell (cfg);
    if (cfg_filesz > CFG_BUFSZ) {
        printf ("x-ray error: config file is too large.\n");
        fclose (cfg);
        return -1;
    }
    rewind (cfg);
    ssize_t nread;
    nread = fread (cfg_buf, 1, cfg_filesz, cfg);
    (void) nread;
    fclose (cfg);
    struct json_value_s * json_root = 
    json_parse_ex (cfg_buf, cfg_filesz, json_parse_flags_allow_hexadecimal_numbers,
    0,0,0);
    if (json_root == NULL) {
        printf ("x-ray error: there is a (json) syntax error in config file.\n");
        return -1;
    }
    struct json_object_s * object = 
    (struct json_object_s*)json_root->payload;
    struct json_object_element_s* elem = object->start;
    struct json_string_s* elem_name;
    struct json_value_s* elem_value;
    while (elem != NULL) {
        elem_name = elem->name;
        elem_value = elem->value;
        set_tvm_info (info, elem_name, elem_value);
        elem = elem->next;
    }
    if (info->stat != TVM_INFO_STAT_BIT_ALL) {
        printf ("x-ray error: missing member in config file.\n");
        return -1;
    } else {
        tvm->stat = TVM_STATE_INFO_LOADED;
    }
    if (strlen (info->sysmap_path) != 0) {
        sysmap = fopen (info->sysmap_path, "r");
        if (!sysmap) {
            printf ("x-ray error: sysmap not found.\n");
        } else {
            setup_tvm (tvm, sysmap);
        }
    }
    return 0;
}

bool x_ray_need_flush_tb (void) {
    if (xray.need_flush_tb) {
        return TRUE;
    } else {
        return FALSE;
    }
}

void x_ray_flush_tb (CPUState *cpu) {
    qemu_spin_lock (&(xray.x_ray_lk));
    if (xray.need_flush_tb) {
        printf ("X-Ray: TB Flushed.\n");
        tb_flush (cpu);
        xray.need_flush_tb = FALSE;
    }
    qemu_spin_unlock (&(xray.x_ray_lk));
}

TVMState * x_ray_get_tvm_state (void) {
    return &(xray.tvm);
}

#define MAX_PROC_NUM 10000

static TVM_task_struct * find_init_task (CPUState *cpu, uint64_t start) {
    TVM_task_struct *ts;
    ts = load_task_struct (cpu, start);
    xray.tvm.init_task_addr = ts->addr;
    int i = 0;
    for (i = 0; i < MAX_PROC_NUM; i++) {
        if (ts->pid == 0) {
            xray.tvm.init_task_addr = ts->addr;
            return ts;
        }
        free (ts);
        ts = load_task_struct (cpu, ts->next_task);
    }
    printf ("x-ray: init_task not found.\n");
    return NULL;
}

/* Lock before preform update */
TVMState * x_ray_update_tvm_state (CPUState *cpu, uint64_t valid_ts_addr) {
    TVMState *tvm;
    TVM_task_struct *ts, *next_ts;
    uint64_t next_ts_addr;
    tvm = &(xray.tvm);
    ts = tvm->init_task.next;
    //qemu_spin_lock (&(xray.tvm_lk));
    // clean tasks
    while (ts != NULL) {
        next_ts = ts->next;
        free (ts);
        ts = next_ts;
    }
    // reload init_task
    ts = find_init_task (cpu, valid_ts_addr);
    // ts = find_init_task (cpu, valid_ts_addr);
    if (ts == NULL)
        return NULL;
    tvm->init_task = *ts;
    free (ts);
    ts = &(tvm->init_task);
    int cnt = 0;
    // load other tasks
    do {
        next_ts_addr = ts->next_task;
        next_ts = load_task_struct (cpu, next_ts_addr);
        next_ts->next = NULL;
        if (next_ts->pid == 0) {
            ts->next = NULL;
            free (next_ts);
            break;
        }
        ts->next = next_ts;
        ts = next_ts;
        cnt++;
    } while (ts->pid != 0 && cnt < MAX_PROC_NUM);
    ts->next = NULL;
    //qemu_spin_unlock (&(xray.tvm_lk));
    return tvm;
}

static const char * symtab_get_name (SymTab *symtab ,uint64_t addr) {
    SymElem *sym;
    if (symtab->len == 0) {
        return NULL;
    }

    if (addr < symtab->syms[0].addr) {
        return "*user*";
    }

    size_t i;
    for (i = 0; i < symtab->len; i++) {
        sym = symtab->syms + i;
        if (i + 1 >= symtab->len) {
            break;
        }
        if (sym->addr <= addr && 
           (sym + 1)->addr > addr) {
            break;
        }
    }
    return sym->sym;
} 

const char * x_ray_get_kernel_func_name (uint64_t addr) {
    // do simple search
    SymTab *syms;
    const char *ret;
    ret = NULL;
    if (xray.tvm.stat == TVM_STATE_XRAY_READY) {
        syms = &(xray.tvm.sym_tab);
        ret = symtab_get_name (syms, addr);
    }
    return ret;
}

static __attribute__ (( unused )) TVM_task_struct* look_up_ts (CPUState *cpu, uint64_t addr) {
    TVM_task_struct* ts;
    qemu_spin_lock (&xray.tvm_lk);
    // look up for ts
    ts = &(xray.tvm.init_task);

    // while (ts != NULL) {
    //     if (ts->addr == addr)
    //         break;
    //     ts = ts->next;
    // }

    // // if not found, reload tasks
    // if (ts == NULL) {
    x_ray_update_tvm_state (cpu, addr);
    // }
    // look up for ts
    while (ts != NULL) {
        if (ts->addr == addr)
            break;
        ts = ts->next;
    }
    // not found ???
    qemu_spin_unlock (&xray.tvm_lk);
    return ts;
}


static __attribute__ (( unused ))  TVM_task_struct* update_ts (CPUState* cpu, TVM_task_struct *ts) {
    TVMState *tvm;
    TVMInfo *info = NULL;
    abi_ptr ptr;
    abi_ptr next_tasks;
    CPUArchState *env;
    env = cpu_env (cpu);
    char buf[TASK_COMM_LEN];
    int i;
    char c;
    tvm = x_ray_get_tvm_state ();
    if (tvm->stat == TVM_STATE_XRAY_READY) {
        info = &(tvm->info);
        ptr = ts->addr + info->linux_name;
        for (i = 0; i < TASK_COMM_LEN; i++) {
            if (i == TASK_COMM_LEN - 1) {
                buf[i] = 0;
                break;
            }
            c = cpu_ldub_data (env, ptr+i);
            buf[i] = c;
            if (c == 0)
                break;
        }
        memcpy (ts->comm, buf, sizeof (ts->comm));
        // pid;
        ptr = ts->addr + info->linux_pid;
        ts->pid = cpu_ldl_data (env, ptr);
        // tgid
        ptr = ts->addr + info->linux_tgid;
        ts->tgid = cpu_ldl_data (env, ptr);
        // next_task
        ptr = ts->addr + info->linux_tasks;
        #if TARGET_LONG_SIZE == 4
        next_tasks = cpu_ldl_data (env, ptr);
        #elif TARGET_LONG_SIZE == 8
        next_tasks = cpu_ldq_data (env, ptr);
        #else
        #error TARGET_LONG_SIZE undefined
        #endif
        ts->next_task = next_tasks - info->linux_tasks;
    } else {
        return NULL;
    }
    return ts;
}

TVM_task_struct* x_ray_update_current_task (CPUState *cpu, uint64_t addr) {
    TVM_task_struct* ts;
    qemu_spin_lock (&xray.tvm_lk);
    x_ray_update_tvm_state (cpu, addr);
    ts = load_task_struct (cpu, addr);
    if (ts == NULL)
        return NULL;
    memcpy (&(cpu->current), ts, sizeof (TVM_task_struct));
    cpu->current.next = NULL;
    free (ts);
    qemu_spin_unlock (&xray.tvm_lk);
    return &(cpu->current);
}

TVM_task_struct* x_ray_get_current_task (CPUState *cpu) {
    return &(cpu->current);
}


bool x_ray_need_insert_hook (CPUState *cpu, uint64_t ptr) {
    size_t i;
    HookList *list = &(xray.hk);
    Hook* hk;
    if (xray.stat == XRAY_READY) {
        for (i = 0; i < list->num; i++) {
            hk = list->hooks + i;
            if (hk->active == TRUE) {
                if (hk->type == HOOK_KERNEL && hk->addr != 0) {
                    if (hk->addr == ptr)
                        return TRUE;
                } else if (hk->type == HOOK_PROCESS) {
                    if (hk->addr == ptr)
                        return TRUE;
                } else {
                    // do nothing
                }
            }
        }
    }
    return FALSE;
}

bool x_ray_is_switch_addr (uint64_t addr) {
    TVMState *tvm;
    tvm = &(xray.tvm);
    if (xray.stat == XRAY_READY && 
        (tvm->stat == TVM_STATE_XRAY_READY)) {
        if (addr == tvm->switch_addr) {
            return TRUE;
        }
    }
    return FALSE;
}

static int add_hook (uint64_t addr, const char * comm, bool proc_hook, xray_callback_t cb) {
    HookList *list = &(xray.hk);
    Hook *hk;
    if (list->num >= MAX_HOOK_NUM)
        return -1;
    hk = list->hooks + list->num;
    list->num++;
    hk->active = true;
    if (proc_hook) {
        hk->type = HOOK_PROCESS;
        hk->comm[0] = 0;
    } else {
        hk->type = HOOK_KERNEL;
        strncpy (hk->comm, comm, TASK_COMM_LEN-1);
        hk->comm[TASK_COMM_LEN-1] = 0;
    }
    hk->cb = cb;
    hk->addr = addr;
    printf ("x-ray: hook added %s @ %lx\n", hk->comm, hk->addr);
    return true;
}

static uint64_t symtab_get_addr (SymTab *symtab ,const char *name) {
    size_t i;

    if (symtab->len == 0) {
        return 0;
    }

    for (i = 0; i < symtab->len; i++) {
        if (!strcmp(symtab->syms[i].sym, name)) {
            return symtab->syms[i].addr;
        }
    }
    return 0;
}

static int update_hooks (void) {
    size_t i;
    HookList *list = &(xray.hk);
    Hook *hk;
    SymTab *syms;
    syms = &(xray.tvm.sym_tab);
    for (i = 0; i < list->num; i++) {
        hk = list->hooks + i; 
        if (hk->type == HOOK_KERNEL) {
            hk->addr = symtab_get_addr (syms, hk->comm);
            printf ("x-ray: hook updated %s @ %lx\n", hk->comm, hk->addr);
        }
    }
    xray.need_flush_tb = TRUE;
    return 1;
}

int x_ray_add_kernel_hook (const char *name, xray_callback_t cb) {
    TVMState *tvm;
    tvm = &(xray.tvm);
    SymTab *syms;
    uint64_t addr;
    int ret;
    syms = &(tvm->sym_tab);
    ret = -1;
    if (xray.stat == XRAY_READY) {
        addr = symtab_get_addr (syms, name);
        ret = add_hook (addr, name, FALSE, cb);
    }
    return ret;
}

int x_ray_add_process_hook (uint64_t ptr, xray_callback_t cb) {
    int ret;
    ret = -1;
    if (xray.stat == XRAY_READY) {
        ret = add_hook (ptr, NULL, TRUE, cb);
    }
    return ret;
}

void x_ray_hook_cb (CPUArchState *env, uint64_t fn_addr) {
    size_t i;
    HookList *hks = &(xray.hk);
    for (i = 0; i < hks->num; i++) {
        if (hks->hooks[i].active && hks->hooks[i].addr == fn_addr) {
            hks->hooks[i].cb (env, fn_addr);
        }
    }
}

void qmp_setup_vmi (const char *cfg_path, Error **errp) {
    printf ("qmp_setup_vmi:%s\n", cfg_path);
    x_ray_tvm_setup (cfg_path);
    update_hooks ();
}

ProcessInfoList* qmp_x_ray_ps (Error **errp) {
    // list all processes

    ProcessInfoList* list;
    list = NULL;
    qemu_spin_lock (&xray.qmp_lk);
    // x_ray_update_tvm_state (cpu);
    qemu_spin_lock (&xray.tvm_lk);
    TVM_task_struct *init_task, *task_ptr;
    ProcessInfo *info;
    init_task = &(xray.tvm.init_task);
    task_ptr = init_task;
    while (task_ptr != NULL) {
        info = g_malloc0 (sizeof(*info));
        info->comm = g_strdup (task_ptr->comm);
        info->tgid = task_ptr->tgid;
        info->pid = task_ptr->pid;
        QAPI_LIST_PREPEND (list, info);
        task_ptr = task_ptr->next;
    }
    qemu_spin_unlock (&xray.tvm_lk);
    qemu_spin_unlock (&xray.qmp_lk);

    return list;
}