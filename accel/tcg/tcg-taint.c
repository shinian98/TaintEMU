#include "qemu/osdep.h"

#include "exec/exec-all.h"
#include "tcg/tcg-taint.h"

CPUArchState * te_get_shadow_env (CPUArchState *env) {
    CPUState *cs = env_cpu (env);
    return (CPUArchState*) &(cs->shadow_env);
}

void * te_get_shadow_stack (CPUArchState *env) {
    CPUState *cs = env_cpu (env);
    return (void*) &(cs->shadow_stack);
}

uint64_t * te_get_shadow_args (CPUArchState *env) {
    CPUState *cs = env_cpu (env);
    return (uint64_t*) &(cs->shadow_reg);
}