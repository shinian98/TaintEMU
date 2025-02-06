#ifndef TCG_TAINT_H
#define TCG_TAINT_H
void taint_write_notify (uint64_t addr, uint64_t taint, uint64_t val, CPUArchState *env);

void taint_read_notify (uint64_t addr, uint64_t taint, uint64_t val, CPUArchState *env);

void taint_exec_notify (uint64_t addr, uint64_t taint); 

CPUArchState * te_get_shadow_env (CPUArchState *env);

void * te_get_shadow_stack (CPUArchState *env);

uint64_t * te_get_shadow_args (CPUArchState *env);

#endif