#define MAX_TASK_NAME_LEN 128
#define MAX_KERNFN_LEN 128
#define MAX_KERNFN_STK_SIZE 256
#define SHADOW_ENV_SIZE 16384
#define SHADOW_STACKS_SIZE 4096
#define SHADOW_REG_NUM 16
#define SHADOW_BUFSZ 4096

uint64_t qemu_ld_temp;
uint64_t qemu_st_temp;
uint8_t shadow_reg [SHADOW_REG_NUM];
uint8_t shadow_stack [SHADOW_STACKS_SIZE];
uint8_t shadow_buf [SHADOW_BUFSZ];
uint8_t shadow_env [SHADOW_ENV_SIZE];