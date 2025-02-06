/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "../tcg-ldst.c.inc"
#include "../tcg-pool.c.inc"

#ifdef CONFIG_DEBUG_TCG
static const char * const tcg_target_reg_names[TCG_TARGET_NB_REGS] = {
#if TCG_TARGET_REG_BITS == 64
    "%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi",
#else
    "%eax", "%ecx", "%edx", "%ebx", "%esp", "%ebp", "%esi", "%edi",
#endif
    "%r8",  "%r9",  "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
    "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7",
#if TCG_TARGET_REG_BITS == 64
    "%xmm8", "%xmm9", "%xmm10", "%xmm11",
    "%xmm12", "%xmm13", "%xmm14", "%xmm15",
#endif
};
#endif

static const int tcg_target_reg_alloc_order[] = {
    TCG_REG_RBP,
    TCG_REG_RBX,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14,
    TCG_REG_R15,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R9,
    TCG_REG_R8,
    TCG_REG_RCX,
    TCG_REG_RDX,
    TCG_REG_RSI,
    TCG_REG_RDI,
    TCG_REG_RAX,
    TCG_REG_XMM0,
    TCG_REG_XMM1,
    TCG_REG_XMM2,
    TCG_REG_XMM3,
    TCG_REG_XMM4,
    TCG_REG_XMM5,
    TCG_REG_XMM6,
    TCG_REG_XMM7,
    TCG_REG_XMM8,
    TCG_REG_XMM9,
    TCG_REG_XMM10,
    TCG_REG_XMM11,
    TCG_REG_XMM12,
    TCG_REG_XMM13,
    TCG_REG_XMM14,
    TCG_REG_XMM15,
};

#define TCG_TMP_VEC  TCG_REG_XMM5

static const int tcg_target_call_iarg_regs[] = {

    TCG_REG_RDI,
    TCG_REG_RSI,
    TCG_REG_RDX,
    TCG_REG_RCX,
    TCG_REG_R8,
    TCG_REG_R9
};

static TCGReg tcg_target_call_oarg_reg(TCGCallReturnKind kind, int slot)
{
    switch (kind) {
    case TCG_CALL_RET_NORMAL:
        tcg_debug_assert(slot >= 0 && slot <= 1);
        return slot ? TCG_REG_EDX : TCG_REG_EAX;
#ifdef _WIN64
    case TCG_CALL_RET_BY_VEC:
        tcg_debug_assert(slot == 0);
        return TCG_REG_XMM0;
#endif
    default:
        g_assert_not_reached();
    }
}

/* Constants we accept.  */
#define TCG_CT_CONST_S32 0x100
#define TCG_CT_CONST_U32 0x200
#define TCG_CT_CONST_I32 0x400
#define TCG_CT_CONST_WSZ 0x800

/* Registers used with L constraint, which are the first argument
   registers on x86_64, and two random call clobbered registers on
   i386. */
#if TCG_TARGET_REG_BITS == 64
# define TCG_REG_L0 tcg_target_call_iarg_regs[0]
# define TCG_REG_L1 tcg_target_call_iarg_regs[1]
#else
# define TCG_REG_L0 TCG_REG_EAX
# define TCG_REG_L1 TCG_REG_EDX
#endif

#if TCG_TARGET_REG_BITS == 64
# define ALL_GENERAL_REGS      0x0000ffffu
# define ALL_VECTOR_REGS       0xffff0000u
# define ALL_BYTEL_REGS        ALL_GENERAL_REGS
#else
# define ALL_GENERAL_REGS      0x000000ffu
# define ALL_VECTOR_REGS       0x00ff0000u
# define ALL_BYTEL_REGS        0x0000000fu
#endif
#define SOFTMMU_RESERVE_REGS \
    (tcg_use_softmmu ? (1 << TCG_REG_L0) | (1 << TCG_REG_L1) : 0)

/* For 64-bit, we always know that CMOV is available.  */
#if TCG_TARGET_REG_BITS == 64
# define have_cmov      true
#else
# define have_cmov      (cpuinfo & CPUINFO_CMOV)
#endif
#define have_bmi2       (cpuinfo & CPUINFO_BMI2)
#define have_lzcnt      (cpuinfo & CPUINFO_LZCNT)

static const tcg_insn_unit *tb_ret_addr;

static bool patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend)
{
    value += addend;
    switch(type) {
    case R_386_PC32:
        value -= (uintptr_t)tcg_splitwx_to_rx(code_ptr);
        if (value != (int32_t)value) {
            return false;
        }
        /* FALLTHRU */
    case R_386_32:
        tcg_patch32(code_ptr, value);
        break;
    case R_386_PC8:
        value -= (uintptr_t)tcg_splitwx_to_rx(code_ptr);
        if (value != (int8_t)value) {
            return false;
        }
        tcg_patch8(code_ptr, value);
        break;
    default:
        g_assert_not_reached();
    }
    return true;
}

/* test if a constant matches the constraint */
static bool tcg_target_const_match(int64_t val, TCGType type, int ct, int vece)
{
    if (ct & TCG_CT_CONST) {
        return 1;
    }
    if (type == TCG_TYPE_I32) {
        if (ct & (TCG_CT_CONST_S32 | TCG_CT_CONST_U32 | TCG_CT_CONST_I32)) {
            return 1;
        }
    } else {
        if ((ct & TCG_CT_CONST_S32) && val == (int32_t)val) {
            return 1;
        }
        if ((ct & TCG_CT_CONST_U32) && val == (uint32_t)val) {
            return 1;
        }
        if ((ct & TCG_CT_CONST_I32) && ~val == (int32_t)~val) {
            return 1;
        }
    }
    if ((ct & TCG_CT_CONST_WSZ) && val == (type == TCG_TYPE_I32 ? 32 : 64)) {
        return 1;
    }
    return 0;
}

# define LOWREGMASK(x)	((x) & 7)

#define P_EXT		0x100		/* 0x0f opcode prefix */
#define P_EXT38         0x200           /* 0x0f 0x38 opcode prefix */
#define P_DATA16        0x400           /* 0x66 opcode prefix */
#define P_VEXW          0x1000          /* Set VEX.W = 1 */
#if TCG_TARGET_REG_BITS == 64
# define P_REXW         P_VEXW          /* Set REX.W = 1; match VEXW */
# define P_REXB_R       0x2000          /* REG field as byte register */
# define P_REXB_RM      0x4000          /* R/M field as byte register */
# define P_GS           0x8000          /* gs segment override */
#else
# define P_REXW		0
# define P_REXB_R	0
# define P_REXB_RM	0
# define P_GS           0
#endif
#define P_EXT3A         0x10000         /* 0x0f 0x3a opcode prefix */
#define P_SIMDF3        0x20000         /* 0xf3 opcode prefix */
#define P_SIMDF2        0x40000         /* 0xf2 opcode prefix */
#define P_VEXL          0x80000         /* Set VEX.L = 1 */
#define P_EVEX          0x100000        /* Requires EVEX encoding */

#define OPC_ARITH_EvIz	(0x81)
#define OPC_ARITH_EvIb	(0x83)
#define OPC_ARITH_GvEv	(0x03)		/* ... plus (ARITH_FOO << 3) */
#define OPC_ANDN        (0xf2 | P_EXT38)
#define OPC_ADD_GvEv	(OPC_ARITH_GvEv | (ARITH_ADD << 3))
#define OPC_AND_GvEv    (OPC_ARITH_GvEv | (ARITH_AND << 3))
#define OPC_BLENDPS     (0x0c | P_EXT3A | P_DATA16)
#define OPC_BSF         (0xbc | P_EXT)
#define OPC_BSR         (0xbd | P_EXT)
#define OPC_BSWAP	(0xc8 | P_EXT)
#define OPC_CALL_Jz	(0xe8)
#define OPC_CMOVCC      (0x40 | P_EXT)  /* ... plus condition code */
#define OPC_CMP_GvEv	(OPC_ARITH_GvEv | (ARITH_CMP << 3))
#define OPC_DEC_r32	(0x48)
#define OPC_IMUL_GvEv	(0xaf | P_EXT)
#define OPC_IMUL_GvEvIb	(0x6b)
#define OPC_IMUL_GvEvIz	(0x69)
#define OPC_INC_r32	(0x40)
#define OPC_JCC_long	(0x80 | P_EXT)	/* ... plus condition code */
#define OPC_JCC_short	(0x70)		/* ... plus condition code */
#define OPC_JMP_long	(0xe9)
#define OPC_JMP_short	(0xeb)
#define OPC_LEA         (0x8d)
#define OPC_LZCNT       (0xbd | P_EXT | P_SIMDF3)
#define OPC_MOVB_EvGv	(0x88)		/* stores, more or less */
#define OPC_MOVL_EvGv	(0x89)		/* stores, more or less */
#define OPC_MOVL_GvEv	(0x8b)		/* loads, more or less */
#define OPC_MOVB_EvIz   (0xc6)
#define OPC_MOVL_EvIz	(0xc7)
#define OPC_MOVB_Ib     (0xb0)
#define OPC_MOVL_Iv     (0xb8)
#define OPC_MOVBE_GyMy  (0xf0 | P_EXT38)
#define OPC_MOVBE_MyGy  (0xf1 | P_EXT38)
#define OPC_MOVD_VyEy   (0x6e | P_EXT | P_DATA16)
#define OPC_MOVD_EyVy   (0x7e | P_EXT | P_DATA16)
#define OPC_MOVDDUP     (0x12 | P_EXT | P_SIMDF2)
#define OPC_MOVDQA_VxWx (0x6f | P_EXT | P_DATA16)
#define OPC_MOVDQA_WxVx (0x7f | P_EXT | P_DATA16)
#define OPC_MOVDQU_VxWx (0x6f | P_EXT | P_SIMDF3)
#define OPC_MOVDQU_WxVx (0x7f | P_EXT | P_SIMDF3)
#define OPC_MOVQ_VqWq   (0x7e | P_EXT | P_SIMDF3)
#define OPC_MOVQ_WqVq   (0xd6 | P_EXT | P_DATA16)
#define OPC_MOVSBL	(0xbe | P_EXT)
#define OPC_MOVSWL	(0xbf | P_EXT)
#define OPC_MOVSLQ	(0x63 | P_REXW)
#define OPC_MOVZBL	(0xb6 | P_EXT)
#define OPC_MOVZWL	(0xb7 | P_EXT)
#define OPC_PABSB       (0x1c | P_EXT38 | P_DATA16)
#define OPC_PABSW       (0x1d | P_EXT38 | P_DATA16)
#define OPC_PABSD       (0x1e | P_EXT38 | P_DATA16)
#define OPC_VPABSQ      (0x1f | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_PACKSSDW    (0x6b | P_EXT | P_DATA16)
#define OPC_PACKSSWB    (0x63 | P_EXT | P_DATA16)
#define OPC_PACKUSDW    (0x2b | P_EXT38 | P_DATA16)
#define OPC_PACKUSWB    (0x67 | P_EXT | P_DATA16)
#define OPC_PADDB       (0xfc | P_EXT | P_DATA16)
#define OPC_PADDW       (0xfd | P_EXT | P_DATA16)
#define OPC_PADDD       (0xfe | P_EXT | P_DATA16)
#define OPC_PADDQ       (0xd4 | P_EXT | P_DATA16)
#define OPC_PADDSB      (0xec | P_EXT | P_DATA16)
#define OPC_PADDSW      (0xed | P_EXT | P_DATA16)
#define OPC_PADDUB      (0xdc | P_EXT | P_DATA16)
#define OPC_PADDUW      (0xdd | P_EXT | P_DATA16)
#define OPC_PAND        (0xdb | P_EXT | P_DATA16)
#define OPC_PANDN       (0xdf | P_EXT | P_DATA16)
#define OPC_PBLENDW     (0x0e | P_EXT3A | P_DATA16)
#define OPC_PCMPEQB     (0x74 | P_EXT | P_DATA16)
#define OPC_PCMPEQW     (0x75 | P_EXT | P_DATA16)
#define OPC_PCMPEQD     (0x76 | P_EXT | P_DATA16)
#define OPC_PCMPEQQ     (0x29 | P_EXT38 | P_DATA16)
#define OPC_PCMPGTB     (0x64 | P_EXT | P_DATA16)
#define OPC_PCMPGTW     (0x65 | P_EXT | P_DATA16)
#define OPC_PCMPGTD     (0x66 | P_EXT | P_DATA16)
#define OPC_PCMPGTQ     (0x37 | P_EXT38 | P_DATA16)
#define OPC_PEXTRD      (0x16 | P_EXT3A | P_DATA16)
#define OPC_PINSRD      (0x22 | P_EXT3A | P_DATA16)
#define OPC_PMAXSB      (0x3c | P_EXT38 | P_DATA16)
#define OPC_PMAXSW      (0xee | P_EXT | P_DATA16)
#define OPC_PMAXSD      (0x3d | P_EXT38 | P_DATA16)
#define OPC_VPMAXSQ     (0x3d | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_PMAXUB      (0xde | P_EXT | P_DATA16)
#define OPC_PMAXUW      (0x3e | P_EXT38 | P_DATA16)
#define OPC_PMAXUD      (0x3f | P_EXT38 | P_DATA16)
#define OPC_VPMAXUQ     (0x3f | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_PMINSB      (0x38 | P_EXT38 | P_DATA16)
#define OPC_PMINSW      (0xea | P_EXT | P_DATA16)
#define OPC_PMINSD      (0x39 | P_EXT38 | P_DATA16)
#define OPC_VPMINSQ     (0x39 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_PMINUB      (0xda | P_EXT | P_DATA16)
#define OPC_PMINUW      (0x3a | P_EXT38 | P_DATA16)
#define OPC_PMINUD      (0x3b | P_EXT38 | P_DATA16)
#define OPC_VPMINUQ     (0x3b | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_PMOVSXBW    (0x20 | P_EXT38 | P_DATA16)
#define OPC_PMOVSXWD    (0x23 | P_EXT38 | P_DATA16)
#define OPC_PMOVSXDQ    (0x25 | P_EXT38 | P_DATA16)
#define OPC_PMOVZXBW    (0x30 | P_EXT38 | P_DATA16)
#define OPC_PMOVZXWD    (0x33 | P_EXT38 | P_DATA16)
#define OPC_PMOVZXDQ    (0x35 | P_EXT38 | P_DATA16)
#define OPC_PMULLW      (0xd5 | P_EXT | P_DATA16)
#define OPC_PMULLD      (0x40 | P_EXT38 | P_DATA16)
#define OPC_VPMULLQ     (0x40 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_POR         (0xeb | P_EXT | P_DATA16)
#define OPC_PSHUFB      (0x00 | P_EXT38 | P_DATA16)
#define OPC_PSHUFD      (0x70 | P_EXT | P_DATA16)
#define OPC_PSHUFLW     (0x70 | P_EXT | P_SIMDF2)
#define OPC_PSHUFHW     (0x70 | P_EXT | P_SIMDF3)
#define OPC_PSHIFTW_Ib  (0x71 | P_EXT | P_DATA16) /* /2 /6 /4 */
#define OPC_PSHIFTD_Ib  (0x72 | P_EXT | P_DATA16) /* /1 /2 /6 /4 */
#define OPC_PSHIFTQ_Ib  (0x73 | P_EXT | P_DATA16) /* /2 /6 /4 */
#define OPC_PSLLW       (0xf1 | P_EXT | P_DATA16)
#define OPC_PSLLD       (0xf2 | P_EXT | P_DATA16)
#define OPC_PSLLQ       (0xf3 | P_EXT | P_DATA16)
#define OPC_PSRAW       (0xe1 | P_EXT | P_DATA16)
#define OPC_PSRAD       (0xe2 | P_EXT | P_DATA16)
#define OPC_VPSRAQ      (0xe2 | P_EXT | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_PSRLW       (0xd1 | P_EXT | P_DATA16)
#define OPC_PSRLD       (0xd2 | P_EXT | P_DATA16)
#define OPC_PSRLQ       (0xd3 | P_EXT | P_DATA16)
#define OPC_PSUBB       (0xf8 | P_EXT | P_DATA16)
#define OPC_PSUBW       (0xf9 | P_EXT | P_DATA16)
#define OPC_PSUBD       (0xfa | P_EXT | P_DATA16)
#define OPC_PSUBQ       (0xfb | P_EXT | P_DATA16)
#define OPC_PSUBSB      (0xe8 | P_EXT | P_DATA16)
#define OPC_PSUBSW      (0xe9 | P_EXT | P_DATA16)
#define OPC_PSUBUB      (0xd8 | P_EXT | P_DATA16)
#define OPC_PSUBUW      (0xd9 | P_EXT | P_DATA16)
#define OPC_PUNPCKLBW   (0x60 | P_EXT | P_DATA16)
#define OPC_PUNPCKLWD   (0x61 | P_EXT | P_DATA16)
#define OPC_PUNPCKLDQ   (0x62 | P_EXT | P_DATA16)
#define OPC_PUNPCKLQDQ  (0x6c | P_EXT | P_DATA16)
#define OPC_PUNPCKHBW   (0x68 | P_EXT | P_DATA16)
#define OPC_PUNPCKHWD   (0x69 | P_EXT | P_DATA16)
#define OPC_PUNPCKHDQ   (0x6a | P_EXT | P_DATA16)
#define OPC_PUNPCKHQDQ  (0x6d | P_EXT | P_DATA16)
#define OPC_PXOR        (0xef | P_EXT | P_DATA16)
#define OPC_POP_r32	(0x58)
#define OPC_POPCNT      (0xb8 | P_EXT | P_SIMDF3)
#define OPC_PUSH_r32	(0x50)
#define OPC_PUSH_Iv	(0x68)
#define OPC_PUSH_Ib	(0x6a)
#define OPC_RET		(0xc3)
#define OPC_SETCC	(0x90 | P_EXT | P_REXB_RM) /* ... plus cc */
#define OPC_SHIFT_1	(0xd1)
#define OPC_SHIFT_Ib	(0xc1)
#define OPC_SHIFT_cl	(0xd3)
#define OPC_SARX        (0xf7 | P_EXT38 | P_SIMDF3)
#define OPC_SHUFPS      (0xc6 | P_EXT)
#define OPC_SHLX        (0xf7 | P_EXT38 | P_DATA16)
#define OPC_SHRX        (0xf7 | P_EXT38 | P_SIMDF2)
#define OPC_SHRD_Ib     (0xac | P_EXT)
#define OPC_TESTL	(0x85)
#define OPC_TZCNT       (0xbc | P_EXT | P_SIMDF3)
#define OPC_UD2         (0x0b | P_EXT)
#define OPC_VPBLENDD    (0x02 | P_EXT3A | P_DATA16)
#define OPC_VPBLENDVB   (0x4c | P_EXT3A | P_DATA16)
#define OPC_VPINSRB     (0x20 | P_EXT3A | P_DATA16)
#define OPC_VPINSRW     (0xc4 | P_EXT | P_DATA16)
#define OPC_VBROADCASTSS (0x18 | P_EXT38 | P_DATA16)
#define OPC_VBROADCASTSD (0x19 | P_EXT38 | P_DATA16)
#define OPC_VPBROADCASTB (0x78 | P_EXT38 | P_DATA16)
#define OPC_VPBROADCASTW (0x79 | P_EXT38 | P_DATA16)
#define OPC_VPBROADCASTD (0x58 | P_EXT38 | P_DATA16)
#define OPC_VPBROADCASTQ (0x59 | P_EXT38 | P_DATA16)
#define OPC_VPERMQ      (0x00 | P_EXT3A | P_DATA16 | P_VEXW)
#define OPC_VPERM2I128  (0x46 | P_EXT3A | P_DATA16 | P_VEXL)
#define OPC_VPROLVD     (0x15 | P_EXT38 | P_DATA16 | P_EVEX)
#define OPC_VPROLVQ     (0x15 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPRORVD     (0x14 | P_EXT38 | P_DATA16 | P_EVEX)
#define OPC_VPRORVQ     (0x14 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSHLDW     (0x70 | P_EXT3A | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSHLDD     (0x71 | P_EXT3A | P_DATA16 | P_EVEX)
#define OPC_VPSHLDQ     (0x71 | P_EXT3A | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSHLDVW    (0x70 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSHLDVD    (0x71 | P_EXT38 | P_DATA16 | P_EVEX)
#define OPC_VPSHLDVQ    (0x71 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSHRDVW    (0x72 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSHRDVD    (0x73 | P_EXT38 | P_DATA16 | P_EVEX)
#define OPC_VPSHRDVQ    (0x73 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSLLVW     (0x12 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSLLVD     (0x47 | P_EXT38 | P_DATA16)
#define OPC_VPSLLVQ     (0x47 | P_EXT38 | P_DATA16 | P_VEXW)
#define OPC_VPSRAVW     (0x11 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSRAVD     (0x46 | P_EXT38 | P_DATA16)
#define OPC_VPSRAVQ     (0x46 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSRLVW     (0x10 | P_EXT38 | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VPSRLVD     (0x45 | P_EXT38 | P_DATA16)
#define OPC_VPSRLVQ     (0x45 | P_EXT38 | P_DATA16 | P_VEXW)
#define OPC_VPTERNLOGQ  (0x25 | P_EXT3A | P_DATA16 | P_VEXW | P_EVEX)
#define OPC_VZEROUPPER  (0x77 | P_EXT)
#define OPC_XCHG_ax_r32	(0x90)
#define OPC_XCHG_EvGv   (0x87)

#define OPC_GRP3_Eb     (0xf6)
#define OPC_GRP3_Ev     (0xf7)
#define OPC_GRP5        (0xff)
#define OPC_GRP14       (0x73 | P_EXT | P_DATA16)

/* Group 1 opcode extensions for 0x80-0x83.
   These are also used as modifiers for OPC_ARITH.  */
#define ARITH_ADD 0
#define ARITH_OR  1
#define ARITH_ADC 2
#define ARITH_SBB 3
#define ARITH_AND 4
#define ARITH_SUB 5
#define ARITH_XOR 6
#define ARITH_CMP 7

/* Group 2 opcode extensions for 0xc0, 0xc1, 0xd0-0xd3.  */
#define SHIFT_ROL 0
#define SHIFT_ROR 1
#define SHIFT_SHL 4
#define SHIFT_SHR 5
#define SHIFT_SAR 7

/* Group 3 opcode extensions for 0xf6, 0xf7.  To be used with OPC_GRP3.  */
#define EXT3_TESTi 0
#define EXT3_NOT   2
#define EXT3_NEG   3
#define EXT3_MUL   4
#define EXT3_IMUL  5
#define EXT3_DIV   6
#define EXT3_IDIV  7

/* Group 5 opcode extensions for 0xff.  To be used with OPC_GRP5.  */
#define EXT5_INC_Ev	0
#define EXT5_DEC_Ev	1
#define EXT5_CALLN_Ev	2
#define EXT5_JMPN_Ev	4

/* Condition codes to be added to OPC_JCC_{long,short}.  */
#define JCC_JMP (-1)
#define JCC_JO  0x0
#define JCC_JNO 0x1
#define JCC_JB  0x2
#define JCC_JAE 0x3
#define JCC_JE  0x4
#define JCC_JNE 0x5
#define JCC_JBE 0x6
#define JCC_JA  0x7
#define JCC_JS  0x8
#define JCC_JNS 0x9
#define JCC_JP  0xa
#define JCC_JNP 0xb
#define JCC_JL  0xc
#define JCC_JGE 0xd
#define JCC_JLE 0xe
#define JCC_JG  0xf

static const uint8_t tcg_cond_to_jcc[] = {
    [TCG_COND_EQ] = JCC_JE,
    [TCG_COND_NE] = JCC_JNE,
    [TCG_COND_LT] = JCC_JL,
    [TCG_COND_GE] = JCC_JGE,
    [TCG_COND_LE] = JCC_JLE,
    [TCG_COND_GT] = JCC_JG,
    [TCG_COND_LTU] = JCC_JB,
    [TCG_COND_GEU] = JCC_JAE,
    [TCG_COND_LEU] = JCC_JBE,
    [TCG_COND_GTU] = JCC_JA,
};

#if TCG_TARGET_REG_BITS == 64
static void tcg_out_opc(TCGContext *s, int opc, int r, int rm, int x)
{
    int rex;

    if (opc & P_GS) {
        tcg_out8(s, 0x65);
    }
    if (opc & P_DATA16) {
        /* We should never be asking for both 16 and 64-bit operation.  */
        tcg_debug_assert((opc & P_REXW) == 0);
        tcg_out8(s, 0x66);
    }
    if (opc & P_SIMDF3) {
        tcg_out8(s, 0xf3);
    } else if (opc & P_SIMDF2) {
        tcg_out8(s, 0xf2);
    }

    rex = 0;
    rex |= (opc & P_REXW) ? 0x8 : 0x0;  /* REX.W */
    rex |= (r & 8) >> 1;                /* REX.R */
    rex |= (x & 8) >> 2;                /* REX.X */
    rex |= (rm & 8) >> 3;               /* REX.B */

    /* P_REXB_{R,RM} indicates that the given register is the low byte.
       For %[abcd]l we need no REX prefix, but for %{si,di,bp,sp}l we do,
       as otherwise the encoding indicates %[abcd]h.  Note that the values
       that are ORed in merely indicate that the REX byte must be present;
       those bits get discarded in output.  */
    rex |= opc & (r >= 4 ? P_REXB_R : 0);
    rex |= opc & (rm >= 4 ? P_REXB_RM : 0);

    if (rex) {
        tcg_out8(s, (uint8_t)(rex | 0x40));
    }

    if (opc & (P_EXT | P_EXT38 | P_EXT3A)) {
        tcg_out8(s, 0x0f);
        if (opc & P_EXT38) {
            tcg_out8(s, 0x38);
        } else if (opc & P_EXT3A) {
            tcg_out8(s, 0x3a);
        }
    }

    tcg_out8(s, opc);
}
#else
static void tcg_out_opc(TCGContext *s, int opc)
{
    if (opc & P_DATA16) {
        tcg_out8(s, 0x66);
    }
    if (opc & P_SIMDF3) {
        tcg_out8(s, 0xf3);
    } else if (opc & P_SIMDF2) {
        tcg_out8(s, 0xf2);
    }
    if (opc & (P_EXT | P_EXT38 | P_EXT3A)) {
        tcg_out8(s, 0x0f);
        if (opc & P_EXT38) {
            tcg_out8(s, 0x38);
        } else if (opc & P_EXT3A) {
            tcg_out8(s, 0x3a);
        }
    }
    tcg_out8(s, opc);
}
/* Discard the register arguments to tcg_out_opc early, so as not to penalize
   the 32-bit compilation paths.  This method works with all versions of gcc,
   whereas relying on optimization may not be able to exclude them.  */
#define tcg_out_opc(s, opc, r, rm, x)  (tcg_out_opc)(s, opc)
#endif

static void tcg_out_modrm(TCGContext *s, int opc, int r, int rm)
{
    tcg_out_opc(s, opc, r, rm, 0);
    tcg_out8(s, 0xc0 | (LOWREGMASK(r) << 3) | LOWREGMASK(rm));
}

static void tcg_out_vex_opc(TCGContext *s, int opc, int r, int v,
                            int rm, int index)
{
    int tmp;

    if (opc & P_GS) {
        tcg_out8(s, 0x65);
    }
    /* Use the two byte form if possible, which cannot encode
       VEX.W, VEX.B, VEX.X, or an m-mmmm field other than P_EXT.  */
    if ((opc & (P_EXT | P_EXT38 | P_EXT3A | P_VEXW)) == P_EXT
        && ((rm | index) & 8) == 0) {
        /* Two byte VEX prefix.  */
        tcg_out8(s, 0xc5);

        tmp = (r & 8 ? 0 : 0x80);              /* VEX.R */
    } else {
        /* Three byte VEX prefix.  */
        tcg_out8(s, 0xc4);

        /* VEX.m-mmmm */
        if (opc & P_EXT3A) {
            tmp = 3;
        } else if (opc & P_EXT38) {
            tmp = 2;
        } else if (opc & P_EXT) {
            tmp = 1;
        } else {
            g_assert_not_reached();
        }
        tmp |= (r & 8 ? 0 : 0x80);             /* VEX.R */
        tmp |= (index & 8 ? 0 : 0x40);         /* VEX.X */
        tmp |= (rm & 8 ? 0 : 0x20);            /* VEX.B */
        tcg_out8(s, tmp);

        tmp = (opc & P_VEXW ? 0x80 : 0);       /* VEX.W */
    }

    tmp |= (opc & P_VEXL ? 0x04 : 0);      /* VEX.L */
    /* VEX.pp */
    if (opc & P_DATA16) {
        tmp |= 1;                          /* 0x66 */
    } else if (opc & P_SIMDF3) {
        tmp |= 2;                          /* 0xf3 */
    } else if (opc & P_SIMDF2) {
        tmp |= 3;                          /* 0xf2 */
    }
    tmp |= (~v & 15) << 3;                 /* VEX.vvvv */
    tcg_out8(s, tmp);
    tcg_out8(s, opc);
}

static void tcg_out_evex_opc(TCGContext *s, int opc, int r, int v,
                             int rm, int index)
{
    /* The entire 4-byte evex prefix; with R' and V' set. */
    uint32_t p = 0x08041062;
    int mm, pp;

    tcg_debug_assert(have_avx512vl);

    /* EVEX.mm */
    if (opc & P_EXT3A) {
        mm = 3;
    } else if (opc & P_EXT38) {
        mm = 2;
    } else if (opc & P_EXT) {
        mm = 1;
    } else {
        g_assert_not_reached();
    }

    /* EVEX.pp */
    if (opc & P_DATA16) {
        pp = 1;                          /* 0x66 */
    } else if (opc & P_SIMDF3) {
        pp = 2;                          /* 0xf3 */
    } else if (opc & P_SIMDF2) {
        pp = 3;                          /* 0xf2 */
    } else {
        pp = 0;
    }

    p = deposit32(p, 8, 2, mm);
    p = deposit32(p, 13, 1, (rm & 8) == 0);             /* EVEX.RXB.B */
    p = deposit32(p, 14, 1, (index & 8) == 0);          /* EVEX.RXB.X */
    p = deposit32(p, 15, 1, (r & 8) == 0);              /* EVEX.RXB.R */
    p = deposit32(p, 16, 2, pp);
    p = deposit32(p, 19, 4, ~v);
    p = deposit32(p, 23, 1, (opc & P_VEXW) != 0);
    p = deposit32(p, 29, 2, (opc & P_VEXL) != 0);

    tcg_out32(s, p);
    tcg_out8(s, opc);
}

static void tcg_out_vex_modrm(TCGContext *s, int opc, int r, int v, int rm)
{
    if (opc & P_EVEX) {
        tcg_out_evex_opc(s, opc, r, v, rm, 0);
    } else {
        tcg_out_vex_opc(s, opc, r, v, rm, 0);
    }
    tcg_out8(s, 0xc0 | (LOWREGMASK(r) << 3) | LOWREGMASK(rm));
}

/* Output an opcode with a full "rm + (index<<shift) + offset" address mode.
   We handle either RM and INDEX missing with a negative value.  In 64-bit
   mode for absolute addresses, ~RM is the size of the immediate operand
   that will follow the instruction.  */

static void tcg_out_sib_offset(TCGContext *s, int r, int rm, int index,
                               int shift, intptr_t offset)
{
    int mod, len;

    if (index < 0 && rm < 0) {
        if (TCG_TARGET_REG_BITS == 64) {
            /* Try for a rip-relative addressing mode.  This has replaced
               the 32-bit-mode absolute addressing encoding.  */
            intptr_t pc = (intptr_t)s->code_ptr + 5 + ~rm;
            intptr_t disp = offset - pc;
            if (disp == (int32_t)disp) {
                tcg_out8(s, (LOWREGMASK(r) << 3) | 5);
                tcg_out32(s, disp);
                return;
            }

            /* Try for an absolute address encoding.  This requires the
               use of the MODRM+SIB encoding and is therefore larger than
               rip-relative addressing.  */
            if (offset == (int32_t)offset) {
                tcg_out8(s, (LOWREGMASK(r) << 3) | 4);
                tcg_out8(s, (4 << 3) | 5);
                tcg_out32(s, offset);
                return;
            }

            /* ??? The memory isn't directly addressable.  */
            g_assert_not_reached();
        } else {
            /* Absolute address.  */
            tcg_out8(s, (r << 3) | 5);
            tcg_out32(s, offset);
            return;
        }
    }

    /* Find the length of the immediate addend.  Note that the encoding
       that would be used for (%ebp) indicates absolute addressing.  */
    if (rm < 0) {
        mod = 0, len = 4, rm = 5;
    } else if (offset == 0 && LOWREGMASK(rm) != TCG_REG_EBP) {
        mod = 0, len = 0;
    } else if (offset == (int8_t)offset) {
        mod = 0x40, len = 1;
    } else {
        mod = 0x80, len = 4;
    }

    /* Use a single byte MODRM format if possible.  Note that the encoding
       that would be used for %esp is the escape to the two byte form.  */
    if (index < 0 && LOWREGMASK(rm) != TCG_REG_ESP) {
        /* Single byte MODRM format.  */
        tcg_out8(s, mod | (LOWREGMASK(r) << 3) | LOWREGMASK(rm));
    } else {
        /* Two byte MODRM+SIB format.  */

        /* Note that the encoding that would place %esp into the index
           field indicates no index register.  In 64-bit mode, the REX.X
           bit counts, so %r12 can be used as the index.  */
        if (index < 0) {
            index = 4;
        } else {
            tcg_debug_assert(index != TCG_REG_ESP);
        }

        tcg_out8(s, mod | (LOWREGMASK(r) << 3) | 4);
        tcg_out8(s, (shift << 6) | (LOWREGMASK(index) << 3) | LOWREGMASK(rm));
    }

    if (len == 1) {
        tcg_out8(s, offset);
    } else if (len == 4) {
        tcg_out32(s, offset);
    }
}

static void tcg_out_modrm_sib_offset(TCGContext *s, int opc, int r, int rm,
                                     int index, int shift, intptr_t offset)
{
    tcg_out_opc(s, opc, r, rm < 0 ? 0 : rm, index < 0 ? 0 : index);
    tcg_out_sib_offset(s, r, rm, index, shift, offset);
}

static void tcg_out_vex_modrm_sib_offset(TCGContext *s, int opc, int r, int v,
                                         int rm, int index, int shift,
                                         intptr_t offset)
{
    tcg_out_vex_opc(s, opc, r, v, rm < 0 ? 0 : rm, index < 0 ? 0 : index);
    tcg_out_sib_offset(s, r, rm, index, shift, offset);
}

/* A simplification of the above with no index or shift.  */
static inline void tcg_out_modrm_offset(TCGContext *s, int opc, int r,
                                        int rm, intptr_t offset)
{
    tcg_out_modrm_sib_offset(s, opc, r, rm, -1, 0, offset);
}

static inline void tcg_out_vex_modrm_offset(TCGContext *s, int opc, int r,
                                            int v, int rm, intptr_t offset)
{
    tcg_out_vex_modrm_sib_offset(s, opc, r, v, rm, -1, 0, offset);
}

/* Output an opcode with an expected reference to the constant pool.  */
static inline void tcg_out_modrm_pool(TCGContext *s, int opc, int r)
{
    tcg_out_opc(s, opc, r, 0, 0);
    /* Absolute for 32-bit, pc-relative for 64-bit.  */
    tcg_out8(s, LOWREGMASK(r) << 3 | 5);
    tcg_out32(s, 0);
}

/* Output an opcode with an expected reference to the constant pool.  */
static inline void tcg_out_vex_modrm_pool(TCGContext *s, int opc, int r)
{
    tcg_out_vex_opc(s, opc, r, 0, 0, 0);
    /* Absolute for 32-bit, pc-relative for 64-bit.  */
    tcg_out8(s, LOWREGMASK(r) << 3 | 5);
    tcg_out32(s, 0);
}

/* Generate dest op= src.  Uses the same ARITH_* codes as tgen_arithi.  */
static inline void tgen_arithr(TCGContext *s, int subop, int dest, int src)
{
    /* Propagate an opcode prefix, such as P_REXW.  */
    int ext = subop & ~0x7;
    subop &= 0x7;

    tcg_out_modrm(s, OPC_ARITH_GvEv + (subop << 3) + ext, dest, src);
}

static bool tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    int rexw = 0;

    if (arg == ret) {
        return true;
    }
    switch (type) {
    case TCG_TYPE_I64:
        rexw = P_REXW;
        /* fallthru */
    case TCG_TYPE_I32:
        if (ret < 16) {
            if (arg < 16) {
                tcg_out_modrm(s, OPC_MOVL_GvEv + rexw, ret, arg);
            } else {
                tcg_out_vex_modrm(s, OPC_MOVD_EyVy + rexw, arg, 0, ret);
            }
        } else {
            if (arg < 16) {
                tcg_out_vex_modrm(s, OPC_MOVD_VyEy + rexw, ret, 0, arg);
            } else {
                tcg_out_vex_modrm(s, OPC_MOVQ_VqWq, ret, 0, arg);
            }
        }
        break;

    case TCG_TYPE_V64:
        tcg_debug_assert(ret >= 16 && arg >= 16);
        tcg_out_vex_modrm(s, OPC_MOVQ_VqWq, ret, 0, arg);
        break;
    case TCG_TYPE_V128:
        tcg_debug_assert(ret >= 16 && arg >= 16);
        tcg_out_vex_modrm(s, OPC_MOVDQA_VxWx, ret, 0, arg);
        break;
    case TCG_TYPE_V256:
        tcg_debug_assert(ret >= 16 && arg >= 16);
        tcg_out_vex_modrm(s, OPC_MOVDQA_VxWx | P_VEXL, ret, 0, arg);
        break;

    default:
        g_assert_not_reached();
    }
    return true;
}

static const int avx2_dup_insn[4] = {
    OPC_VPBROADCASTB, OPC_VPBROADCASTW,
    OPC_VPBROADCASTD, OPC_VPBROADCASTQ,
};

static void tcg_out_save_shadow_reg (TCGContext *s);

static void tcg_out_restore_shadow_reg (TCGContext *s);

static void tcg_out_zero_shadow_reg (TCGContext *s);
static bool tcg_out_broadcast_vec(TCGContext *s, TCGType type, unsigned vece,
                            TCGReg r, TCGReg a)
{
    if (have_avx2) {
        int vex_l = (type == TCG_TYPE_V256 ? P_VEXL : 0);
        tcg_out_vex_modrm(s, avx2_dup_insn[vece] + vex_l, r, 0, a);
    } else {
        switch (vece) {
        case MO_8:
            /* ??? With zero in a register, use PSHUFB.  */
            tcg_out_vex_modrm(s, OPC_PUNPCKLBW, r, a, a);
            a = r;
            /* FALLTHRU */
        case MO_16:
            tcg_out_vex_modrm(s, OPC_PUNPCKLWD, r, a, a);
            a = r;
            /* FALLTHRU */
        case MO_32:
            tcg_out_vex_modrm(s, OPC_PSHUFD, r, 0, a);
            /* imm8 operand: all output lanes selected from input lane 0.  */
            tcg_out8(s, 0);
            break;
        case MO_64:
            tcg_out_vex_modrm(s, OPC_PUNPCKLQDQ, r, a, a);
            break;
        default:
            g_assert_not_reached();
        }
    }
    return true;
}

// static bool tcg_out_dupm_vec(TCGContext *s, TCGType type, unsigned vece,
//                              TCGReg r, TCGReg base, intptr_t offset)
// {
//     if (have_avx2) {
//         int vex_l = (type == TCG_TYPE_V256 ? P_VEXL : 0);
//         tcg_out_vex_modrm_offset(s, avx2_dup_insn[vece] + vex_l,
//                                  r, 0, base, offset);
//     } else {
//         switch (vece) {
//         case MO_64:
//             tcg_out_vex_modrm_offset(s, OPC_MOVDDUP, r, 0, base, offset);
//             break;
//         case MO_32:
//             tcg_out_vex_modrm_offset(s, OPC_VBROADCASTSS, r, 0, base, offset);
//             break;
//         case MO_16:
//             tcg_out_vex_modrm_offset(s, OPC_VPINSRW, r, r, base, offset);
//             tcg_out8(s, 0); /* imm8 */
//             tcg_out_dup_vec(s, type, vece, r, r);
//             break;
//         case MO_8:
//             tcg_out_vex_modrm_offset(s, OPC_VPINSRB, r, r, base, offset);
//             tcg_out8(s, 0); /* imm8 */
//             tcg_out_dup_vec(s, type, vece, r, r);
//             break;
//         default:
//             g_assert_not_reached();
//         }
//     }
//     return true;
// }

// static void tcg_out_dupi_vec(TCGContext *s, TCGType type, unsigned vece,
//                              TCGReg ret, int64_t arg)
// {
//     int vex_l = (type == TCG_TYPE_V256 ? P_VEXL : 0);

//     if (arg == 0) {
//         tcg_out_vex_modrm(s, OPC_PXOR, ret, ret, ret);
//         return;
//     }
//     if (arg == -1) {
//         tcg_out_vex_modrm(s, OPC_PCMPEQB + vex_l, ret, ret, ret);
//         return;
//     }

//     if (TCG_TARGET_REG_BITS == 32 && vece < MO_64) {
//         if (have_avx2) {
//             tcg_out_vex_modrm_pool(s, OPC_VPBROADCASTD + vex_l, ret);
//         } else {
//             tcg_out_vex_modrm_pool(s, OPC_VBROADCASTSS, ret);
//         }
//         new_pool_label(s, arg, R_386_32, s->code_ptr - 4, 0);
//     } else {
//         if (type == TCG_TYPE_V64) {
//             tcg_out_vex_modrm_pool(s, OPC_MOVQ_VqWq, ret);
//         } else if (have_avx2) {
//             tcg_out_vex_modrm_pool(s, OPC_VPBROADCASTQ + vex_l, ret);
//         } else {
//             tcg_out_vex_modrm_pool(s, OPC_MOVDDUP, ret);
//         }
//         if (TCG_TARGET_REG_BITS == 64) {
//             new_pool_label(s, arg, R_386_PC32, s->code_ptr - 4, -4);
//         } else {
//             new_pool_l2(s, R_386_32, s->code_ptr - 4, 0, arg, arg >> 32);
//         }
//     }
// }

static void tcg_out_movi_vec(TCGContext *s, TCGType type,
                             TCGReg ret, tcg_target_long arg)
{
    if (arg == 0) {
        tcg_out_vex_modrm(s, OPC_PXOR, ret, ret, ret);
        return;
    }
    if (arg == -1) {
        tcg_out_vex_modrm(s, OPC_PCMPEQB, ret, ret, ret);
        return;
    }

    int rexw = (type == TCG_TYPE_I32 ? 0 : P_REXW);
    tcg_out_vex_modrm_pool(s, OPC_MOVD_VyEy + rexw, ret);
    if (TCG_TARGET_REG_BITS == 64) {
        new_pool_label(s, arg, R_386_PC32, s->code_ptr - 4, -4);
    } else {
        new_pool_label(s, arg, R_386_32, s->code_ptr - 4, 0);
    }
}

static void tcg_out_movi_int(TCGContext *s, TCGType type,
                             TCGReg ret, tcg_target_long arg)
{
    tcg_target_long diff;

    if (arg == 0) {
        tgen_arithr(s, ARITH_XOR, ret, ret);
        return;
    }
    if (arg == (uint32_t)arg || type == TCG_TYPE_I32) {
        tcg_out_opc(s, OPC_MOVL_Iv + LOWREGMASK(ret), 0, ret, 0);
        tcg_out32(s, arg);
        return;
    }
    if (arg == (int32_t)arg) {
        tcg_out_modrm(s, OPC_MOVL_EvIz + P_REXW, 0, ret);
        tcg_out32(s, arg);
        return;
    }

    /* Try a 7 byte pc-relative lea before the 10 byte movq.  */
    diff = tcg_pcrel_diff(s, (const void *)arg) - 7;
    if (diff == (int32_t)diff) {
        tcg_out_opc(s, OPC_LEA | P_REXW, ret, 0, 0);
        tcg_out8(s, (LOWREGMASK(ret) << 3) | 5);
        tcg_out32(s, diff);
        return;
    }

    tcg_out_opc(s, OPC_MOVL_Iv + P_REXW + LOWREGMASK(ret), 0, ret, 0);
    tcg_out64(s, arg);
}

static void tcg_out_movi(TCGContext *s, TCGType type,
                         TCGReg ret, tcg_target_long arg)
{
    switch (type) {
    case TCG_TYPE_I32:
#if TCG_TARGET_REG_BITS == 64
    case TCG_TYPE_I64:
#endif
        if (ret < 16) {
            tcg_out_movi_int(s, type, ret, arg);
            /* clean taint */
            tcg_out_movi_vec(s, type, shadow_reg(type), 0);
        } else {
            tcg_out_movi_vec(s, type, ret, arg);
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static bool tcg_out_xchg(TCGContext *s, TCGType type, TCGReg r1, TCGReg r2)
{
    int rexw = type == TCG_TYPE_I32 ? 0 : P_REXW;
    tcg_out_modrm(s, OPC_XCHG_EvGv + rexw, r1, r2);
    return true;
}

static void tcg_out_addi_ptr(TCGContext *s, TCGReg rd, TCGReg rs,
                             tcg_target_long imm)
{
    /* This function is only used for passing structs by reference. */
    tcg_debug_assert(imm == (int32_t)imm);
    tcg_out_modrm_offset(s, OPC_LEA | P_REXW, rd, rs, imm);
}

static inline void tcg_out_pushi(TCGContext *s, tcg_target_long val)
{
    if (val == (int8_t)val) {
        tcg_out_opc(s, OPC_PUSH_Ib, 0, 0, 0);
        tcg_out8(s, val);
    } else if (val == (int32_t)val) {
        tcg_out_opc(s, OPC_PUSH_Iv, 0, 0, 0);
        tcg_out32(s, val);
    } else {
        g_assert_not_reached();
    }
}

static inline void tcg_out_mb(TCGContext *s, TCGArg a0)
{
    /* Given the strength of x86 memory ordering, we only need care for
       store-load ordering.  Experimentally, "lock orl $0,0(%esp)" is
       faster than "mfence", so don't bother with the sse insn.  */
    if (a0 & TCG_MO_ST_LD) {
        tcg_out8(s, 0xf0);
        tcg_out_modrm_offset(s, OPC_ARITH_EvIb, ARITH_OR, TCG_REG_ESP, 0);
        tcg_out8(s, 0);
    }
}

static inline void tcg_out_push(TCGContext *s, int reg)
{
    tcg_out_opc(s, OPC_PUSH_r32 + LOWREGMASK(reg), 0, reg, 0);
}

static inline void tcg_out_pop(TCGContext *s, int reg)
{
    tcg_out_opc(s, OPC_POP_r32 + LOWREGMASK(reg), 0, reg, 0);
}

static void tcg_out_ld(TCGContext *s, TCGType type, TCGReg ret,
                       TCGReg arg1, intptr_t arg2)
{
    switch (type) {
    case TCG_TYPE_I32:
        if (ret < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_GvEv, ret, arg1, arg2);
        } else {
            tcg_out_vex_modrm_offset(s, OPC_MOVD_VyEy, ret, 0, arg1, arg2);
        }
        break;
    case TCG_TYPE_I64:
        if (ret < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_GvEv | P_REXW, ret, arg1, arg2);
            break;
        }
        /* FALLTHRU */
    case TCG_TYPE_V64:
        /* There is no instruction that can validate 8-byte alignment.  */
        tcg_debug_assert(ret >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVQ_VqWq, ret, 0, arg1, arg2);
        break;
    case TCG_TYPE_V128:
        /*
         * The gvec infrastructure is asserts that v128 vector loads
         * and stores use a 16-byte aligned offset.  Validate that the
         * final pointer is aligned by using an insn that will SIGSEGV.
         */
        tcg_debug_assert(ret >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVDQA_VxWx, ret, 0, arg1, arg2);
        break;
    case TCG_TYPE_V256:
        /*
         * The gvec infrastructure only requires 16-byte alignment,
         * so here we must use an unaligned load.
         */
        tcg_debug_assert(ret >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVDQU_VxWx | P_VEXL,
                                 ret, 0, arg1, arg2);
        break;
    default:
        g_assert_not_reached();
    }
}

static void tcg_out_st(TCGContext *s, TCGType type, TCGReg arg,
                       TCGReg arg1, intptr_t arg2)
{
    switch (type) {
    case TCG_TYPE_I32:
        if (arg < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv, arg, arg1, arg2);
        } else {
            tcg_out_vex_modrm_offset(s, OPC_MOVD_EyVy, arg, 0, arg1, arg2);
        }
        break;
    case TCG_TYPE_I64:
        if (arg < 16) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv | P_REXW, arg, arg1, arg2);
            break;
        }
        /* FALLTHRU */
    case TCG_TYPE_V64:
        /* There is no instruction that can validate 8-byte alignment.  */
        tcg_debug_assert(arg >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVQ_WqVq, arg, 0, arg1, arg2);
        break;
    case TCG_TYPE_V128:
        /*
         * The gvec infrastructure is asserts that v128 vector loads
         * and stores use a 16-byte aligned offset.  Validate that the
         * final pointer is aligned by using an insn that will SIGSEGV.
         *
         * This specific instance is also used by TCG_CALL_RET_BY_VEC,
         * for _WIN64, which must have SSE2 but may not have AVX.
         */
        tcg_debug_assert(arg >= 16);
        if (have_avx1) {
            tcg_out_vex_modrm_offset(s, OPC_MOVDQA_WxVx, arg, 0, arg1, arg2);
        } else {
            tcg_out_modrm_offset(s, OPC_MOVDQA_WxVx, arg, arg1, arg2);
        }
        break;
    case TCG_TYPE_V256:
        /*
         * The gvec infrastructure only requires 16-byte alignment,
         * so here we must use an unaligned store.
         */
        tcg_debug_assert(arg >= 16);
        tcg_out_vex_modrm_offset(s, OPC_MOVDQU_WxVx | P_VEXL,
                                 arg, 0, arg1, arg2);
        break;
    default:
        g_assert_not_reached();
    }
}

static bool tcg_out_sti(TCGContext *s, TCGType type, TCGArg val,
                        TCGReg base, intptr_t ofs)
{
    int rexw = 0;
    if (TCG_TARGET_REG_BITS == 64 && type == TCG_TYPE_I64) {
        if (val != (int32_t)val) {
            return false;
        }
        rexw = P_REXW;
    } else if (type != TCG_TYPE_I32) {
        return false;
    }
    tcg_out_modrm_offset(s, OPC_MOVL_EvIz | rexw, 0, base, ofs);
    tcg_out32(s, val);
    return true;
}

static void tcg_out_shifti(TCGContext *s, int subopc, int reg, int count)
{
    /* Propagate an opcode prefix, such as P_DATA16.  */
    int ext = subopc & ~0x7;
    subopc &= 0x7;

    if (count == 1) {
        tcg_out_modrm(s, OPC_SHIFT_1 + ext, subopc, reg);
    } else {
        tcg_out_modrm(s, OPC_SHIFT_Ib + ext, subopc, reg);
        tcg_out8(s, count);
    }
}

static inline void tcg_out_bswap32(TCGContext *s, int reg)
{
    tcg_out_opc(s, OPC_BSWAP + LOWREGMASK(reg), 0, reg, 0);
}

static inline void tcg_out_rolw_8(TCGContext *s, int reg)
{
    tcg_out_shifti(s, SHIFT_ROL + P_DATA16, reg, 8);
}

static void tcg_out_ext8u(TCGContext *s, TCGReg dest, TCGReg src)
{
    if (dest != src) {
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (dest), shadow_reg (src));
    }
    /* movzbl */
    tcg_debug_assert(src < 4 || TCG_TARGET_REG_BITS == 64);
    tcg_out_modrm(s, OPC_MOVZBL + P_REXB_RM, dest, src);
}

static void tcg_out_ext8s(TCGContext *s, TCGType type, TCGReg dest, TCGReg src)
{
    if (dest != src) {
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (dest), shadow_reg (src));
    }
    int rexw = type == TCG_TYPE_I32 ? 0 : P_REXW;
    /* movsbl */
    tcg_debug_assert(src < 4 || TCG_TARGET_REG_BITS == 64);
    tcg_out_modrm(s, OPC_MOVSBL + P_REXB_RM + rexw, dest, src);
}

static void tcg_out_ext16u(TCGContext *s, TCGReg dest, TCGReg src)
{
    if (dest != src) {
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (dest), shadow_reg (src));
    }
    /* movzwl */
    tcg_out_modrm(s, OPC_MOVZWL, dest, src);
}

static void tcg_out_ext16s(TCGContext *s, TCGType type, TCGReg dest, TCGReg src)
{
    if (dest != src) {
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (dest), shadow_reg (src));
    }
    int rexw = type == TCG_TYPE_I32 ? 0 : P_REXW;
    /* movsw[lq] */
    tcg_out_modrm(s, OPC_MOVSWL + rexw, dest, src);
}

static void tcg_out_ext32u(TCGContext *s, TCGReg dest, TCGReg src)
{
    if (dest != src) {
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (dest), shadow_reg (src));
    }
    /* 32-bit mov zero extends.  */
    tcg_out_modrm(s, OPC_MOVL_GvEv, dest, src);
}

static void tcg_out_ext32s(TCGContext *s, TCGReg dest, TCGReg src)
{
    if (dest != src) {
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (dest), shadow_reg (src));
    }
    tcg_debug_assert(TCG_TARGET_REG_BITS == 64);
    tcg_out_modrm(s, OPC_MOVSLQ, dest, src);
}

static void tcg_out_exts_i32_i64(TCGContext *s, TCGReg dest, TCGReg src)
{
    tcg_out_ext32s(s, dest, src);
}

static void tcg_out_extu_i32_i64(TCGContext *s, TCGReg dest, TCGReg src)
{
    if (dest != src) {
        tcg_out_ext32u(s, dest, src);
    }
}

static void tcg_out_extrl_i64_i32(TCGContext *s, TCGReg dest, TCGReg src)
{
    tcg_out_ext32u(s, dest, src);
}

static inline void tcg_out_bswap64(TCGContext *s, int reg)
{
    tcg_out_opc(s, OPC_BSWAP + P_REXW + LOWREGMASK(reg), 0, reg, 0);
}

static void tgen_arithi(TCGContext *s, int c, int r0,
                        tcg_target_long val, int cf)
{
    int rexw = 0;

    if (TCG_TARGET_REG_BITS == 64) {
        rexw = c & -8;
        c &= 7;
    }

    /* ??? While INC is 2 bytes shorter than ADDL $1, they also induce
       partial flags update stalls on Pentium4 and are not recommended
       by current Intel optimization manuals.  */
    if (!cf && (c == ARITH_ADD || c == ARITH_SUB) && (val == 1 || val == -1)) {
        int is_inc = (c == ARITH_ADD) ^ (val < 0);
        if (TCG_TARGET_REG_BITS == 64) {
            /* The single-byte increment encodings are re-tasked as the
               REX prefixes.  Use the MODRM encoding.  */
            tcg_out_modrm(s, OPC_GRP5 + rexw,
                          (is_inc ? EXT5_INC_Ev : EXT5_DEC_Ev), r0);
        } else {
            tcg_out8(s, (is_inc ? OPC_INC_r32 : OPC_DEC_r32) + r0);
        }
        return;
    }

    if (c == ARITH_AND) {
        if (TCG_TARGET_REG_BITS == 64) {
            if (val == 0xffffffffu) {
                tcg_out_ext32u(s, r0, r0);
                return;
            }
            if (val == (uint32_t)val) {
                /* AND with no high bits set can use a 32-bit operation.  */
                rexw = 0;
            }
        }
        if (val == 0xffu && (r0 < 4 || TCG_TARGET_REG_BITS == 64)) {
            tcg_out_ext8u(s, r0, r0);
            return;
        }
        if (val == 0xffffu) {
            tcg_out_ext16u(s, r0, r0);
            return;
        }
    }

    if (val == (int8_t)val) {
        tcg_out_modrm(s, OPC_ARITH_EvIb + rexw, c, r0);
        tcg_out8(s, val);
        return;
    }
    if (rexw == 0 || val == (int32_t)val) {
        tcg_out_modrm(s, OPC_ARITH_EvIz + rexw, c, r0);
        tcg_out32(s, val);
        return;
    }

    g_assert_not_reached();
}

static void tcg_out_addi(TCGContext *s, int reg, tcg_target_long val)
{
    if (val != 0) {
        tgen_arithi(s, ARITH_ADD + P_REXW, reg, val, 0);
    }
}

/* Set SMALL to force a short forward branch.  */
static void tcg_out_jxx(TCGContext *s, int opc, TCGLabel *l, bool small)
{
    int32_t val, val1;

    if (l->has_value) {
        val = tcg_pcrel_diff(s, l->u.value_ptr);
        val1 = val - 2;
        if ((int8_t)val1 == val1) {
            if (opc == -1) {
                tcg_out8(s, OPC_JMP_short);
            } else {
                tcg_out8(s, OPC_JCC_short + opc);
            }
            tcg_out8(s, val1);
        } else {
            tcg_debug_assert(!small);
            if (opc == -1) {
                tcg_out8(s, OPC_JMP_long);
                tcg_out32(s, val - 5);
            } else {
                tcg_out_opc(s, OPC_JCC_long + opc, 0, 0, 0);
                tcg_out32(s, val - 6);
            }
        }
    } else if (small) {
        if (opc == -1) {
            tcg_out8(s, OPC_JMP_short);
        } else {
            tcg_out8(s, OPC_JCC_short + opc);
        }
        tcg_out_reloc(s, s->code_ptr, R_386_PC8, l, -1);
        s->code_ptr += 1;
    } else {
        if (opc == -1) {
            tcg_out8(s, OPC_JMP_long);
        } else {
            tcg_out_opc(s, OPC_JCC_long + opc, 0, 0, 0);
        }
        tcg_out_reloc(s, s->code_ptr, R_386_PC32, l, -4);
        s->code_ptr += 4;
    }
}

static void tcg_out_cmp(TCGContext *s, TCGArg arg1, TCGArg arg2,
                        int const_arg2, int rexw)
{
    if (const_arg2) {
        if (arg2 == 0) {
            /* test r, r */
            tcg_out_modrm(s, OPC_TESTL + rexw, arg1, arg1);
        } else {
            tgen_arithi(s, ARITH_CMP + rexw, arg1, arg2, 0);
        }
    } else {
        tgen_arithr(s, ARITH_CMP + rexw, arg1, arg2);
    }
}

static void tcg_out_brcond(TCGContext *s, int rexw, TCGCond cond,
                           TCGArg arg1, TCGArg arg2, int const_arg2,
                           TCGLabel *label, bool small)
{
    tcg_out_cmp(s, arg1, arg2, const_arg2, rexw);
    tcg_out_jxx(s, tcg_cond_to_jcc[cond], label, small);
}

#if TCG_TARGET_REG_BITS == 32
static void tcg_out_brcond2(TCGContext *s, const TCGArg *args,
                            const int *const_args, bool small)
{
    TCGLabel *label_next = gen_new_label();
    TCGLabel *label_this = arg_label(args[5]);

    switch(args[4]) {
    case TCG_COND_EQ:
        tcg_out_brcond(s, 0, TCG_COND_NE, args[0], args[2], const_args[2],
                       label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_EQ, args[1], args[3], const_args[3],
                       label_this, small);
        break;
    case TCG_COND_NE:
        tcg_out_brcond(s, 0, TCG_COND_NE, args[0], args[2], const_args[2],
                       label_this, small);
        tcg_out_brcond(s, 0, TCG_COND_NE, args[1], args[3], const_args[3],
                       label_this, small);
        break;
    case TCG_COND_LT:
        tcg_out_brcond(s, 0, TCG_COND_LT, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_LTU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    case TCG_COND_LE:
        tcg_out_brcond(s, 0, TCG_COND_LT, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_LEU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    case TCG_COND_GT:
        tcg_out_brcond(s, 0, TCG_COND_GT, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_GTU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    case TCG_COND_GE:
        tcg_out_brcond(s, 0, TCG_COND_GT, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_GEU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    case TCG_COND_LTU:
        tcg_out_brcond(s, 0, TCG_COND_LTU, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_LTU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    case TCG_COND_LEU:
        tcg_out_brcond(s, 0, TCG_COND_LTU, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_LEU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    case TCG_COND_GTU:
        tcg_out_brcond(s, 0, TCG_COND_GTU, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_GTU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    case TCG_COND_GEU:
        tcg_out_brcond(s, 0, TCG_COND_GTU, args[1], args[3], const_args[3],
                       label_this, small);
        tcg_out_jxx(s, JCC_JNE, label_next, 1);
        tcg_out_brcond(s, 0, TCG_COND_GEU, args[0], args[2], const_args[2],
                       label_this, small);
        break;
    default:
        g_assert_not_reached();
    }
    tcg_out_label(s, label_next);
}
#endif

static void tcg_out_setcond(TCGContext *s, int rexw, TCGCond cond,
                            TCGArg dest, TCGArg arg1, TCGArg arg2,
                            int const_arg2, bool neg)
{
    bool inv = false;
    bool cleared;

    switch (cond) {
    case TCG_COND_NE:
        inv = true;
        /* fall through */
    case TCG_COND_EQ:
        /* If arg2 is 0, convert to LTU/GEU vs 1. */
        if (const_arg2 && arg2 == 0) {
            arg2 = 1;
            goto do_ltu;
        }
        break;

    case TCG_COND_LEU:
        inv = true;
        /* fall through */
    case TCG_COND_GTU:
        /* If arg2 is a register, swap for LTU/GEU. */
        if (!const_arg2) {
            TCGReg t = arg1;
            arg1 = arg2;
            arg2 = t;
            goto do_ltu;
        }
        break;

    case TCG_COND_GEU:
        inv = true;
        /* fall through */
    case TCG_COND_LTU:
    do_ltu:
        /*
         * Relying on the carry bit, use SBB to produce -1 if LTU, 0 if GEU.
         * We can then use NEG or INC to produce the desired result.
         * This is always smaller than the SETCC expansion.
         */
        tcg_out_cmp(s, arg1, arg2, const_arg2, rexw);

        /* X - X - C = -C = (C ? -1 : 0) */
        tgen_arithr(s, ARITH_SBB + (neg ? rexw : 0), dest, dest);
        if (inv && neg) {
            /* ~(C ? -1 : 0) = (C ? 0 : -1) */
            tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_NOT, dest);
        } else if (inv) {
            /* (C ? -1 : 0) + 1 = (C ? 0 : 1) */
            tgen_arithi(s, ARITH_ADD, dest, 1, 0);
        } else if (!neg) {
            /* -(C ? -1 : 0) = (C ? 1 : 0) */
            tcg_out_modrm(s, OPC_GRP3_Ev, EXT3_NEG, dest);
        }
        return;

    case TCG_COND_GE:
        inv = true;
        /* fall through */
    case TCG_COND_LT:
        /* If arg2 is 0, extract the sign bit. */
        if (const_arg2 && arg2 == 0) {
            tcg_out_mov(s, rexw ? TCG_TYPE_I64 : TCG_TYPE_I32, dest, arg1);
            if (inv) {
                tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_NOT, dest);
            }
            tcg_out_shifti(s, (neg ? SHIFT_SAR : SHIFT_SHR) + rexw,
                           dest, rexw ? 63 : 31);
            return;
        }
        break;

    default:
        break;
    }

    /*
     * If dest does not overlap the inputs, clearing it first is preferred.
     * The XOR breaks any false dependency for the low-byte write to dest,
     * and is also one byte smaller than MOVZBL.
     */
    cleared = false;
    if (dest != arg1 && (const_arg2 || dest != arg2)) {
        tgen_arithr(s, ARITH_XOR, dest, dest);
        cleared = true;
    }

    tcg_out_cmp(s, arg1, arg2, const_arg2, rexw);
    tcg_out_modrm(s, OPC_SETCC | tcg_cond_to_jcc[cond], 0, dest);

    if (!cleared) {
        tcg_out_ext8u(s, dest, dest);
    }
    if (neg) {
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_NEG, dest);
    }
}

#if TCG_TARGET_REG_BITS == 32
static void tcg_out_setcond2(TCGContext *s, const TCGArg *args,
                             const int *const_args)
{
    TCGArg new_args[6];
    TCGLabel *label_true, *label_over;

    memcpy(new_args, args+1, 5*sizeof(TCGArg));

    if (args[0] == args[1] || args[0] == args[2]
        || (!const_args[3] && args[0] == args[3])
        || (!const_args[4] && args[0] == args[4])) {
        /* When the destination overlaps with one of the argument
           registers, don't do anything tricky.  */
        label_true = gen_new_label();
        label_over = gen_new_label();

        new_args[5] = label_arg(label_true);
        tcg_out_brcond2(s, new_args, const_args+1, 1);

        tcg_out_movi(s, TCG_TYPE_I32, args[0], 0);
        tcg_out_jxx(s, JCC_JMP, label_over, 1);
        tcg_out_label(s, label_true);

        tcg_out_movi(s, TCG_TYPE_I32, args[0], 1);
        tcg_out_label(s, label_over);
    } else {
        /* When the destination does not overlap one of the arguments,
           clear the destination first, jump if cond false, and emit an
           increment in the true case.  This results in smaller code.  */

        tcg_out_movi(s, TCG_TYPE_I32, args[0], 0);

        label_over = gen_new_label();
        new_args[4] = tcg_invert_cond(new_args[4]);
        new_args[5] = label_arg(label_over);
        tcg_out_brcond2(s, new_args, const_args+1, 1);

        tgen_arithi(s, ARITH_ADD, args[0], 1, 0);
        tcg_out_label(s, label_over);
    }
}
#endif

static void tcg_out_cmov(TCGContext *s, TCGCond cond, int rexw,
                         TCGReg dest, TCGReg v1)
{
    if (have_cmov) {
        tcg_out_modrm(s, OPC_CMOVCC | tcg_cond_to_jcc[cond] | rexw, dest, v1);
    } else {
        TCGLabel *over = gen_new_label();
        tcg_out_jxx(s, tcg_cond_to_jcc[tcg_invert_cond(cond)], over, 1);
        tcg_out_mov(s, TCG_TYPE_I32, dest, v1);
        tcg_out_label(s, over);
    }
}

static void tcg_out_movcond(TCGContext *s, int rexw, TCGCond cond,
                            TCGReg dest, TCGReg c1, TCGArg c2, int const_c2,
                            TCGReg v1)
{
    tcg_out_cmp(s, c1, c2, const_c2, rexw);
    tcg_out_cmov(s, cond, rexw, dest, v1);
}

static void tcg_out_ctz(TCGContext *s, int rexw, TCGReg dest, TCGReg arg1,
                        TCGArg arg2, bool const_a2)
{
    if (have_bmi1) {
        tcg_out_modrm(s, OPC_TZCNT + rexw, dest, arg1);
        if (const_a2) {
            tcg_debug_assert(arg2 == (rexw ? 64 : 32));
        } else {
            tcg_debug_assert(dest != arg2);
            tcg_out_cmov(s, TCG_COND_LTU, rexw, dest, arg2);
        }
    } else {
        tcg_debug_assert(dest != arg2);
        tcg_out_modrm(s, OPC_BSF + rexw, dest, arg1);
        tcg_out_cmov(s, TCG_COND_EQ, rexw, dest, arg2);
    }
}

static void tcg_out_clz(TCGContext *s, int rexw, TCGReg dest, TCGReg arg1,
                        TCGArg arg2, bool const_a2)
{
    if (have_lzcnt) {
        tcg_out_modrm(s, OPC_LZCNT + rexw, dest, arg1);
        if (const_a2) {
            tcg_debug_assert(arg2 == (rexw ? 64 : 32));
        } else {
            tcg_debug_assert(dest != arg2);
            tcg_out_cmov(s, TCG_COND_LTU, rexw, dest, arg2);
        }
    } else {
        tcg_debug_assert(!const_a2);
        tcg_debug_assert(dest != arg1);
        tcg_debug_assert(dest != arg2);

        /* Recall that the output of BSR is the index not the count.  */
        tcg_out_modrm(s, OPC_BSR + rexw, dest, arg1);
        tgen_arithi(s, ARITH_XOR + rexw, dest, rexw ? 63 : 31, 0);

        /* Since we have destroyed the flags from BSR, we have to re-test.  */
        tcg_out_cmp(s, arg1, 0, 1, rexw);
        tcg_out_cmov(s, TCG_COND_EQ, rexw, dest, arg2);
    }
}

static void tcg_out_branch(TCGContext *s, int call, const tcg_insn_unit *dest)
{
    intptr_t disp = tcg_pcrel_diff(s, dest) - 5;

    if (disp == (int32_t)disp) {
        tcg_out_opc(s, call ? OPC_CALL_Jz : OPC_JMP_long, 0, 0, 0);
        tcg_out32(s, disp);
    } else {
        /* rip-relative addressing into the constant pool.
           This is 6 + 8 = 14 bytes, as compared to using an
           immediate load 10 + 6 = 16 bytes, plus we may
           be able to re-use the pool constant for more calls.  */
        tcg_out_opc(s, OPC_GRP5, 0, 0, 0);
        tcg_out8(s, (call ? EXT5_CALLN_Ev : EXT5_JMPN_Ev) << 3 | 5);
        new_pool_label(s, (uintptr_t)dest, R_386_PC32, s->code_ptr, -4);
        tcg_out32(s, 0);
    }
}


static void __attribute__((unused)) tcg_out_or_vec (TCGContext *s, TCGReg rd, TCGReg rs1, TCGReg rs2) {
    tcg_out_vex_modrm(s, OPC_POR, rd, rs1, rs2);
}

static void __attribute__((unused)) tcg_out_xor_vec (TCGContext *s, TCGReg rd, TCGReg rs1, TCGReg rs2) {
    tcg_out_vex_modrm(s, OPC_PXOR, rd, rs1, rs2);
}

static void __attribute__((unused)) tcg_out_add_vec (TCGContext *s, TCGReg rd, TCGReg rs1, TCGReg rs2) {
    tcg_out_vex_modrm(s, OPC_PADDQ, rd, rs1, rs2);
}

static void __attribute__((unused)) tcg_out_sub_vec (TCGContext *s, TCGReg rd, TCGReg rs1, TCGReg rs2) {
    tcg_out_vex_modrm(s, OPC_PSUBQ, rd, rs1, rs2);
}

static void __attribute__((unused)) tcg_out_and_vec (TCGContext *s, TCGReg rd, TCGReg rs1, TCGReg rs2) {
    tcg_out_vex_modrm(s, OPC_PAND, rd, rs1, rs2);
}

static void __attribute__((unused)) tcg_out_andn_vec (TCGContext *s, TCGReg rd, TCGReg rs1, TCGReg rs2) {
    tcg_out_vex_modrm(s, OPC_PANDN, rd, rs2, rs1);
}

static void __attribute__((unused)) tcg_out_test_vec (TCGContext *s, TCGReg rd, TCGReg rs) {
    tcg_out_modrm(s, OPC_PANDN, rd, rs);
}

static void __attribute__((unused)) tcg_out_rotli_vec (TCGContext *s, TCGReg rd, TCGReg rs, unsigned vece, uint8_t imm) {
    int insn, sub;
    insn = OPC_PSHIFTD_Ib | P_EVEX;
    sub = 1;
    tcg_out_vex_modrm(s, insn, sub, rd, rs);
    tcg_out8(s, imm);
}

static void __attribute__((unused)) tcg_out_union_vec_64 (TCGContext *s, TCGReg r) {
    /* if we have avx512... */
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP0, r, MO_32, 8);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP0);
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP1, r, MO_32, 16);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP1);
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP2, r, MO_32, 24);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP2);
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP3, r, MO_64, 32);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP3);

    tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP0, r);
    tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP1, TCG_REG_TEMP0);
    tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP3, TCG_REG_TEMP0);
    tcg_out_shifti(s, SHIFT_ROL + P_REXW, TCG_REG_TEMP1, 8);
    tcg_out_shifti(s, SHIFT_ROR + P_REXW, TCG_REG_TEMP3, 8);
    tgen_arithr(s, ARITH_OR + P_REXW, TCG_REG_TEMP0, TCG_REG_TEMP1);
    tgen_arithr(s, ARITH_OR + P_REXW, TCG_REG_TEMP0, TCG_REG_TEMP3);
    tcg_out_shifti(s, SHIFT_ROL + P_REXW, TCG_REG_TEMP1, 16);
    tcg_out_shifti(s, SHIFT_ROR + P_REXW, TCG_REG_TEMP3, 16);
    tgen_arithr(s, ARITH_OR + P_REXW, TCG_REG_TEMP0, TCG_REG_TEMP1);
    tgen_arithr(s, ARITH_OR + P_REXW, TCG_REG_TEMP0, TCG_REG_TEMP3);
    tcg_out_shifti(s, SHIFT_ROL + P_REXW, TCG_REG_TEMP1, 24);
    tcg_out_shifti(s, SHIFT_ROR + P_REXW, TCG_REG_TEMP3, 24);
    tgen_arithr(s, ARITH_OR + P_REXW, TCG_REG_TEMP0, TCG_REG_TEMP1);
    tgen_arithr(s, ARITH_OR + P_REXW, TCG_REG_TEMP0, TCG_REG_TEMP3);
    tcg_out_shifti(s, SHIFT_ROR + P_REXW, TCG_REG_TEMP3, 32);
    tgen_arithr(s, ARITH_OR + P_REXW, TCG_REG_TEMP0, TCG_REG_TEMP3);
    tcg_out_mov (s, TCG_TYPE_I64, r, TCG_REG_TEMP0);
}

static void __attribute__((unused)) tcg_out_union_vec_32 (TCGContext *s, TCGReg r) {
    /* if we have avx512... */
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP0, r, MO_32, 8);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP0);
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP1, r, MO_32, 16);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP1);
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP2, r, MO_32, 24);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP2);
    // tcg_out_rotli_vec (s, TCG_SHADOW_TEMP3, r, MO_64, 32);
    // tcg_out_or_vec (s, r, r, TCG_SHADOW_TEMP3);

    tcg_out_mov (s, TCG_TYPE_I32, TCG_REG_TEMP0, r);
    tcg_out_mov (s, TCG_TYPE_I32, TCG_REG_TEMP1, TCG_REG_TEMP0);
    tcg_out_shifti(s, SHIFT_ROL, TCG_REG_TEMP1, 8);
    tgen_arithr(s, ARITH_OR, TCG_REG_TEMP0, TCG_REG_TEMP1);
    tcg_out_shifti(s, SHIFT_ROL, TCG_REG_TEMP1, 16);
    tgen_arithr(s, ARITH_OR, TCG_REG_TEMP0, TCG_REG_TEMP1);
    tcg_out_shifti(s, SHIFT_ROL, TCG_REG_TEMP1, 24);
    tgen_arithr(s, ARITH_OR, TCG_REG_TEMP0, TCG_REG_TEMP1);
    tcg_out_mov (s, TCG_TYPE_I64, r, TCG_REG_TEMP0);
}


static void tcg_out_call(TCGContext *s, const tcg_insn_unit *dest,
                         const TCGHelperInfo *info)
{
    tcg_out_movi (s, TCG_TYPE_I64, shadow_reg(TCG_REG_RAX), 0);
    tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), 
                                shadow_reg (tcg_target_call_iarg_regs[0]));
    tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), 
                                shadow_reg (tcg_target_call_iarg_regs[1]));
    tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), 
                                shadow_reg (tcg_target_call_iarg_regs[2]));
    tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), 
                                shadow_reg (tcg_target_call_iarg_regs[3]));
    tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), 
                                shadow_reg (tcg_target_call_iarg_regs[4]));
    tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), 
                                shadow_reg (tcg_target_call_iarg_regs[5]));
    tcg_out_save_shadow_reg (s);
    tcg_out_branch(s, 1, dest);
    tcg_out_restore_shadow_reg (s);

}

static void tcg_out_jmp(TCGContext *s, const tcg_insn_unit *dest)
{
    tcg_out_branch(s, 0, dest);
}

static void tcg_out_nopn(TCGContext *s, int n)
{
    int i;
    /* Emit 1 or 2 operand size prefixes for the standard one byte nop,
     * "xchg %eax,%eax", forming "xchg %ax,%ax". All cores accept the
     * duplicate prefix, and all of the interesting recent cores can
     * decode and discard the duplicates in a single cycle.
     */
    tcg_debug_assert(n >= 1);
    for (i = 1; i < n; ++i) {
        tcg_out8(s, 0x66);
    }
    tcg_out8(s, 0x90);
}

/* Test register R vs immediate bits I, setting Z flag for EQ/NE. */
static void __attribute__((unused))
tcg_out_testi(TCGContext *s, TCGReg r, uint32_t i)
{
    /*
     * This is used for testing alignment, so we can usually use testb.
     * For i686, we have to use testl for %esi/%edi.
     */
    if (i <= 0xff && (TCG_TARGET_REG_BITS == 64 || r < 4)) {
        tcg_out_modrm(s, OPC_GRP3_Eb | P_REXB_RM, EXT3_TESTi, r);
        tcg_out8(s, i);
    } else {
        tcg_out_modrm(s, OPC_GRP3_Ev, EXT3_TESTi, r);
        tcg_out32(s, i);
    }
}

typedef struct {
    TCGReg base;
    TCGReg sbase;
    int index;
    int sindex;
    int ofs;
    int seg;
    TCGAtomAlign aa;
} HostAddress;

bool tcg_target_has_memory_bswap(MemOp memop)
{
    TCGAtomAlign aa;

    if (!have_movbe) {
        return false;
    }
    if ((memop & MO_SIZE) < MO_128) {
        return true;
    }

    /*
     * Reject 16-byte memop with 16-byte atomicity, i.e. VMOVDQA,
     * but do allow a pair of 64-bit operations, i.e. MOVBEQ.
     */
    aa = atom_and_align_for_opc(tcg_ctx, memop, MO_ATOM_IFALIGN, true);
    return aa.atom < MO_128;
}

/*
 * Because i686 has no register parameters and because x86_64 has xchg
 * to handle addr/data register overlap, we have placed all input arguments
 * before we need might need a scratch reg.
 *
 * Even then, a scratch is only needed for l->raddr.  Rather than expose
 * a general-purpose scratch when we don't actually know it's available,
 * use the ra_gen hook to load into RAX if needed.
 */
#if TCG_TARGET_REG_BITS == 64
static TCGReg ldst_ra_gen(TCGContext *s, const TCGLabelQemuLdst *l, int arg)
{
    if (arg < 0) {
        arg = TCG_REG_RAX;
    }
    tcg_out_movi(s, TCG_TYPE_PTR, arg, (uintptr_t)l->raddr);
    return arg;
}
static const TCGLdstHelperParam ldst_helper_param = {
    .ra_gen = ldst_ra_gen
};
#else
static const TCGLdstHelperParam ldst_helper_param = { };
#endif

// static void tcg_out_vec_to_pair(TCGContext *s, TCGType type,
//                                 TCGReg l, TCGReg h, TCGReg v)
// {
//     int rexw = type == TCG_TYPE_I32 ? 0 : P_REXW;

//     /* vpmov{d,q} %v, %l */
//     tcg_out_vex_modrm(s, OPC_MOVD_EyVy + rexw, v, 0, l);
//     /* vpextr{d,q} $1, %v, %h */
//     tcg_out_vex_modrm(s, OPC_PEXTRD + rexw, v, 0, h);
//     tcg_out8(s, 1);
// }

static void tcg_out_pair_to_vec(TCGContext *s, TCGType type,
                                TCGReg v, TCGReg l, TCGReg h)
{
    int rexw = type == TCG_TYPE_I32 ? 0 : P_REXW;

    /* vmov{d,q} %l, %v */
    tcg_out_vex_modrm(s, OPC_MOVD_VyEy + rexw, v, 0, l);
    /* vpinsr{d,q} $1, %h, %v, %v */
    tcg_out_vex_modrm(s, OPC_PINSRD + rexw, v, v, h);
    tcg_out8(s, 1);
}

/*
 * Generate code for the slow path for a load at the end of block
 */
static bool tcg_out_qemu_ld_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    MemOp opc = get_memop(l->oi);
    tcg_insn_unit **label_ptr = &l->label_ptr[0];

    /* resolve label address */
    tcg_patch32(label_ptr[0], s->code_ptr - label_ptr[0] - 4);
    if (label_ptr[1]) {
        tcg_patch32(label_ptr[1], s->code_ptr - label_ptr[1] - 4);
    }

    tcg_out_ld_helper_args(s, l, &ldst_helper_param);
    tcg_out_save_shadow_reg (s);
    tcg_out_branch(s, 1, qemu_ld_helpers[opc & MO_SIZE]);
    tcg_out_restore_shadow_reg (s);
    tcg_out_ld_helper_ret(s, l, false, &ldst_helper_param);
    // taint -> shadow reg
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_TEMP3 ,TCG_AREG0, offsetof (CPUState, qemu_ld_temp) - sizeof (CPUState));
    tcg_out_jmp(s, l->raddr);
    return true;
}

/*
 * Generate code for the slow path for a store at the end of block
 */
static bool tcg_out_qemu_st_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    MemOp opc = get_memop(l->oi);
    tcg_insn_unit **label_ptr = &l->label_ptr[0];

    /* resolve label address */
    tcg_patch32(label_ptr[0], s->code_ptr - label_ptr[0] - 4);
    if (label_ptr[1]) {
        tcg_patch32(label_ptr[1], s->code_ptr - label_ptr[1] - 4);
    }
    // save taint
    tcg_out_st(s, TCG_TYPE_I64, shadow_reg(l->datalo_reg), TCG_AREG0,
                                offsetof(CPUState, qemu_st_temp) - sizeof (CPUState));
    tcg_out_st_helper_args(s, l, &ldst_helper_param);
    tcg_out_save_shadow_reg (s);
    tcg_out_branch(s, 1, qemu_st_helpers[opc & MO_SIZE]);
    tcg_out_restore_shadow_reg (s);


    tcg_out_jmp(s, l->raddr);
    return true;
}

#ifdef CONFIG_USER_ONLY
static HostAddress x86_guest_base = {
    .index = -1
};

#if defined(__x86_64__) && defined(__linux__)
# include <asm/prctl.h>
# include <sys/prctl.h>
int arch_prctl(int code, unsigned long addr);
static inline int setup_guest_base_seg(void)
{
    if (arch_prctl(ARCH_SET_GS, guest_base) == 0) {
        return P_GS;
    }
    return 0;
}
#define setup_guest_base_seg  setup_guest_base_seg
#elif defined(__x86_64__) && \
      (defined (__FreeBSD__) || defined (__FreeBSD_kernel__))
# include <machine/sysarch.h>
static inline int setup_guest_base_seg(void)
{
    if (sysarch(AMD64_SET_GSBASE, &guest_base) == 0) {
        return P_GS;
    }
    return 0;
}
#define setup_guest_base_seg  setup_guest_base_seg
#endif
#else
# define x86_guest_base (*(HostAddress *)({ qemu_build_not_reached(); NULL; }))
#endif /* CONFIG_USER_ONLY */
#ifndef setup_guest_base_seg
# define setup_guest_base_seg()  0
#endif

#define MIN_TLB_MASK_TABLE_OFS  INT_MIN

/*
 * For softmmu, perform the TLB load and compare.
 * For useronly, perform any required alignment tests.
 * In both cases, return a TCGLabelQemuLdst structure if the slow path
 * is required and fill in @h with the host address for the fast path.
 */
static TCGLabelQemuLdst *prepare_host_addr(TCGContext *s, HostAddress *h,
                                           TCGReg addrlo, TCGReg addrhi,
                                           MemOpIdx oi, bool is_ld)
{
    TCGLabelQemuLdst *ldst = NULL;
    MemOp opc = get_memop(oi);
    MemOp s_bits = opc & MO_SIZE;
    unsigned a_mask;

    if (tcg_use_softmmu) {
        h->index = TCG_REG_L0;
        h->ofs = 0;
        h->seg = 0;
    } else {
        *h = x86_guest_base;
    }
    h->base = addrlo;
    h->sbase = TCG_REG_TEMP1;
    h->sindex = TCG_REG_TEMP0;
    h->aa = atom_and_align_for_opc(s, opc, MO_ATOM_IFALIGN, s_bits == MO_128);
    a_mask = (1 << h->aa.align) - 1;

    if (tcg_use_softmmu) {
        tcg_out_mov (s, TCG_TYPE_PTR, TCG_REG_TEMP1, addrlo);
        int cmp_ofs = is_ld ? offsetof(CPUTLBEntry, addr_read)
                            : offsetof(CPUTLBEntry, addr_write);
        TCGType ttype = TCG_TYPE_I32;
        TCGType tlbtype = TCG_TYPE_I32;
        int trexw = 0, hrexw = 0, tlbrexw = 0;
        unsigned mem_index = get_mmuidx(oi);
        unsigned s_mask = (1 << s_bits) - 1;
        int fast_ofs = tlb_mask_table_ofs(s, mem_index);
        int tlb_mask;

        ldst = new_ldst_label(s);
        ldst->is_ld = is_ld;
        ldst->oi = oi;
        ldst->addrlo_reg = addrlo;
        ldst->addrhi_reg = addrhi;

        if (TCG_TARGET_REG_BITS == 64) {
            ttype = s->addr_type;
            trexw = (ttype == TCG_TYPE_I32 ? 0 : P_REXW);
            if (TCG_TYPE_PTR == TCG_TYPE_I64) {
                hrexw = P_REXW;
                if (s->page_bits + s->tlb_dyn_max_bits > 32) {
                    tlbtype = TCG_TYPE_I64;
                    tlbrexw = P_REXW;
                }
            }
        }

        tcg_out_mov(s, tlbtype, TCG_REG_L0, addrlo);
        tcg_out_shifti(s, SHIFT_SHR + tlbrexw, TCG_REG_L0,
                       s->page_bits - CPU_TLB_ENTRY_BITS);

        tcg_out_modrm_offset(s, OPC_AND_GvEv + trexw, TCG_REG_L0, TCG_AREG0,
                             fast_ofs + offsetof(CPUTLBDescFast, mask));

        tcg_out_modrm_offset(s, OPC_ADD_GvEv + hrexw, TCG_REG_L0, TCG_AREG0,
                             fast_ofs + offsetof(CPUTLBDescFast, table));

        /*
         * If the required alignment is at least as large as the access,
         * simply copy the address and mask.  For lesser alignments,
         * check that we don't cross pages for the complete access.
         */
        if (a_mask >= s_mask) {
            tcg_out_mov(s, ttype, TCG_REG_L1, addrlo);
        } else {
            tcg_out_modrm_offset(s, OPC_LEA + trexw, TCG_REG_L1,
                                 addrlo, s_mask - a_mask);
        }
        tlb_mask = s->page_mask | a_mask;
        tgen_arithi(s, ARITH_AND + trexw, TCG_REG_L1, tlb_mask, 0);

        /* cmp 0(TCG_REG_L0), TCG_REG_L1 */
        tcg_out_modrm_offset(s, OPC_CMP_GvEv + trexw,
                             TCG_REG_L1, TCG_REG_L0, cmp_ofs);

        /* jne slow_path */
        tcg_out_opc(s, OPC_JCC_long + JCC_JNE, 0, 0, 0);
        ldst->label_ptr[0] = s->code_ptr;
        s->code_ptr += 4;

        if (TCG_TARGET_REG_BITS == 32 && s->addr_type == TCG_TYPE_I64) {
            /* cmp 4(TCG_REG_L0), addrhi */
            tcg_out_modrm_offset(s, OPC_CMP_GvEv, addrhi,
                                 TCG_REG_L0, cmp_ofs + 4);

            /* jne slow_path */
            tcg_out_opc(s, OPC_JCC_long + JCC_JNE, 0, 0, 0);
            ldst->label_ptr[1] = s->code_ptr;
            s->code_ptr += 4;
        }

        /* TLB Hit.  */
        tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_TEMP0, TCG_REG_L0,
                   offsetof(CPUTLBEntry, shadow_addend));
        tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_L0, TCG_REG_L0,
                   offsetof(CPUTLBEntry, addend)); // vaddr -> haddr
        tgen_arithr (s, ARITH_ADD + P_REXW, TCG_REG_TEMP0, TCG_REG_L0); // vaddr -> haddr -> saddr
        
    } else if (a_mask) {
        ldst = new_ldst_label(s);

        ldst->is_ld = is_ld;
        ldst->oi = oi;
        ldst->addrlo_reg = addrlo;
        ldst->addrhi_reg = addrhi;

        tcg_out_testi(s, addrlo, a_mask);
        /* jne slow_path */
        tcg_out_opc(s, OPC_JCC_long + JCC_JNE, 0, 0, 0);
        ldst->label_ptr[0] = s->code_ptr;
        s->code_ptr += 4;
    }

    return ldst;
}

static void tcg_out_qemu_ld_direct(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   HostAddress h, TCGType type, MemOp memop)
{
    bool use_movbe = false;
    int rexw = (type == TCG_TYPE_I32 ? 0 : P_REXW);
    int movop = OPC_MOVL_GvEv;

    /* Do big-endian loads with movbe.  */
    if (memop & MO_BSWAP) {
        tcg_debug_assert(have_movbe);
        use_movbe = true;
        movop = OPC_MOVBE_GyMy;
    }

    switch (memop & MO_SSIZE) {
    case MO_UB:
        tcg_out_modrm_sib_offset(s, OPC_MOVZBL + h.seg, datalo,
                                 h.base, h.index, 0, h.ofs);
        break;
    case MO_SB:
        tcg_out_modrm_sib_offset(s, OPC_MOVSBL + rexw + h.seg, datalo,
                                 h.base, h.index, 0, h.ofs);
        break;
    case MO_UW:
        if (use_movbe) {
            /* There is no extending movbe; only low 16-bits are modified.  */
            if (datalo != h.base && datalo != h.index) {
                /* XOR breaks dependency chains.  */
                tgen_arithr(s, ARITH_XOR, datalo, datalo);
                tcg_out_modrm_sib_offset(s, OPC_MOVBE_GyMy + P_DATA16 + h.seg,
                                         datalo, h.base, h.index, 0, h.ofs);
            } else {
                tcg_out_modrm_sib_offset(s, OPC_MOVBE_GyMy + P_DATA16 + h.seg,
                                         datalo, h.base, h.index, 0, h.ofs);
                tcg_out_ext16u(s, datalo, datalo);
            }
        } else {
            tcg_out_modrm_sib_offset(s, OPC_MOVZWL + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
        }
        break;
    case MO_SW:
        if (use_movbe) {
            tcg_out_modrm_sib_offset(s, OPC_MOVBE_GyMy + P_DATA16 + h.seg,
                                     datalo, h.base, h.index, 0, h.ofs);
            tcg_out_ext16s(s, type, datalo, datalo);
        } else {
            tcg_out_modrm_sib_offset(s, OPC_MOVSWL + rexw + h.seg,
                                     datalo, h.base, h.index, 0, h.ofs);
        }
        break;
    case MO_UL:
        tcg_out_modrm_sib_offset(s, movop + h.seg, datalo,
                                 h.base, h.index, 0, h.ofs);
        break;
#if TCG_TARGET_REG_BITS == 64
    case MO_SL:
        if (use_movbe) {
            tcg_out_modrm_sib_offset(s, OPC_MOVBE_GyMy + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
            tcg_out_ext32s(s, datalo, datalo);
        } else {
            tcg_out_modrm_sib_offset(s, OPC_MOVSLQ + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
        }
        break;
#endif
    case MO_UQ:
        if (TCG_TARGET_REG_BITS == 64) {
            tcg_out_modrm_sib_offset(s, movop + P_REXW + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
            break;
        }
        if (use_movbe) {
            TCGReg t = datalo;
            datalo = datahi;
            datahi = t;
        }
        if (h.base == datalo || h.index == datalo) {
            tcg_out_modrm_sib_offset(s, OPC_LEA, datahi,
                                     h.base, h.index, 0, h.ofs);
            tcg_out_modrm_offset(s, movop + h.seg, datalo, datahi, 0);
            tcg_out_modrm_offset(s, movop + h.seg, datahi, datahi, 4);
        } else {
            tcg_out_modrm_sib_offset(s, movop + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
            tcg_out_modrm_sib_offset(s, movop + h.seg, datahi,
                                     h.base, h.index, 0, h.ofs + 4);
        }
        break;

    default:
        g_assert_not_reached();
    }
}

static void tcg_out_qemu_ld_taint(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   HostAddress h, TCGType type, MemOp memop)
{
    bool use_movbe = false;
    int movop = OPC_MOVL_GvEv;
    (void) datahi;
    /* Do big-endian loads with movbe.  */
    if (memop & MO_BSWAP) {
        tcg_debug_assert(have_movbe);
        use_movbe = true;
        movop = OPC_MOVBE_GyMy;
    }

    switch (memop & MO_SSIZE) {
    case MO_UB:
    case MO_SB:
        tcg_out_modrm_sib_offset(s, OPC_MOVZBL + h.seg, datalo,
                                 h.sbase, h.sindex, 0, h.ofs);
        break;
    case MO_UW:
    case MO_SW:
        if (use_movbe) {
            /* There is no extending movbe; only low 16-bits are modified.  */
            if (datalo != h.sbase && datalo != h.sindex) {
                /* XOR breaks dependency chains.  */
                tgen_arithr(s, ARITH_XOR, datalo, datalo);
                tcg_out_modrm_sib_offset(s, OPC_MOVBE_GyMy + P_DATA16 + h.seg,
                                         datalo, h.sbase, h.sindex, 0, h.ofs);
            } else {
                tcg_out_modrm_sib_offset(s, OPC_MOVBE_GyMy + P_DATA16 + h.seg,
                                         datalo, h.sbase, h.sindex, 0, h.ofs);
                tcg_out_ext16u(s, datalo, datalo);
            }
        } else {
            tcg_out_modrm_sib_offset(s, OPC_MOVZWL + h.seg, datalo,
                                     h.sbase, h.sindex, 0, h.ofs);
        }
        break;
    case MO_UL:
    case MO_SL:
        tcg_out_modrm_sib_offset(s, movop + h.seg, datalo,
                                 h.sbase, h.sindex, 0, h.ofs);
        break;
    case MO_UQ:
        tcg_out_modrm_sib_offset(s, movop + P_REXW + h.seg, datalo,
                                    h.sbase, h.sindex, 0, h.ofs);
        break;

    default:
        g_assert_not_reached();
    }
}

#include "tcg/tcg-taint.h"

static void tcg_out_qemu_ld(TCGContext *s, TCGReg datalo, TCGReg datahi,
                            TCGReg addrlo, TCGReg addrhi,
                            MemOpIdx oi, TCGType data_type)
{
    TCGLabelQemuLdst *ldst;
    HostAddress h;
    tcg_insn_unit *je_label[2];

    ldst = prepare_host_addr(s, &h, addrlo, addrhi, oi, true);
    tcg_out_qemu_ld_direct(s, datalo, datahi, h, data_type, get_memop(oi));
    tcg_out_qemu_ld_taint(s, TCG_REG_TEMP3, 0, h, data_type, get_memop(oi));

    if (ldst) {
        ldst->type = data_type;
        ldst->datalo_reg = datalo;
        ldst->datahi_reg = datahi;
        ldst->raddr = tcg_splitwx_to_rx(s->code_ptr);
    }

    tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (datalo), TCG_REG_TEMP3);
    tcg_out_cmp (s, TCG_REG_TEMP3, 0, 1, P_REXW);
    tcg_out8 (s, OPC_JCC_short + JCC_JE);
    je_label[0] = s->code_ptr;
    tcg_out8 (s, 0);
    tcg_out_mov(s, TCG_TYPE_I64, TCG_REG_TEMP0, datalo);
    tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[0], TCG_REG_TEMP1); // address 
    tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[1], shadow_reg(datalo)); // taint
    tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[2], datalo); // data
    tcg_out_mov(s, TCG_TYPE_PTR, tcg_target_call_iarg_regs[3], TCG_AREG0); // env
    tcg_out_branch(s, 1, (tcg_insn_unit *)taint_read_notify);
    tcg_out_zero_shadow_reg (s);
    tcg_out_mov (s, TCG_TYPE_I64, datalo, TCG_REG_TEMP0);
    je_label[1] = s->code_ptr;
    tcg_patch8 (je_label[0], je_label[1] - je_label[0]-1);
    tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (datalo), TCG_REG_TEMP3);

}

static void tcg_out_qemu_st_direct(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   HostAddress h, MemOp memop)
{
    bool use_movbe = false;
    int movop = OPC_MOVL_EvGv;

    /*
     * Do big-endian stores with movbe or system-mode.
     * User-only without movbe will have its swapping done generically.
     */
    if (memop & MO_BSWAP) {
        tcg_debug_assert(have_movbe);
        use_movbe = true;
        movop = OPC_MOVBE_MyGy;
    }

    switch (memop & MO_SIZE) {
    case MO_8:
        /* This is handled with constraints on INDEX_op_qemu_st8_i32. */
        tcg_debug_assert(TCG_TARGET_REG_BITS == 64 || datalo < 4);
        tcg_out_modrm_sib_offset(s, OPC_MOVB_EvGv + P_REXB_R + h.seg,
                                 datalo, h.base, h.index, 0, h.ofs);
        break;
    case MO_16:
        tcg_out_modrm_sib_offset(s, movop + P_DATA16 + h.seg, datalo,
                                 h.base, h.index, 0, h.ofs);
        break;
    case MO_32:
        tcg_out_modrm_sib_offset(s, movop + h.seg, datalo,
                                 h.base, h.index, 0, h.ofs);
        break;
    case MO_64:
        if (TCG_TARGET_REG_BITS == 64) {
            tcg_out_modrm_sib_offset(s, movop + P_REXW + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
        } else {
            if (use_movbe) {
                TCGReg t = datalo;
                datalo = datahi;
                datahi = t;
            }
            tcg_out_modrm_sib_offset(s, movop + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
            tcg_out_modrm_sib_offset(s, movop + h.seg, datahi,
                                     h.base, h.index, 0, h.ofs + 4);
        }
        break;

    case MO_128:
        tcg_debug_assert(TCG_TARGET_REG_BITS == 64);

        /*
         * Without 16-byte atomicity, use integer regs.
         * That is where we have the data, and it allows bswaps.
         */
        if (h.aa.atom < MO_128) {
            if (use_movbe) {
                TCGReg t = datalo;
                datalo = datahi;
                datahi = t;
            }
            tcg_out_modrm_sib_offset(s, movop + P_REXW + h.seg, datalo,
                                     h.base, h.index, 0, h.ofs);
            tcg_out_modrm_sib_offset(s, movop + P_REXW + h.seg, datahi,
                                     h.base, h.index, 0, h.ofs + 8);
            break;
        }

        /*
         * With 16-byte atomicity, a vector store is required.
         * If we already have 16-byte alignment, then VMOVDQA always works.
         * Else if VMOVDQU has atomicity with dynamic alignment, use that.
         * Else use we require a runtime test for alignment for VMOVDQA;
         * use VMOVDQU on the unaligned nonatomic path for simplicity.
         */
        tcg_out_pair_to_vec(s, TCG_TYPE_I64, TCG_TMP_VEC, datalo, datahi);
        if (h.aa.align >= MO_128) {
            tcg_out_vex_modrm_sib_offset(s, OPC_MOVDQA_WxVx + h.seg,
                                         TCG_TMP_VEC, 0,
                                         h.base, h.index, 0, h.ofs);
        } else if (cpuinfo & CPUINFO_ATOMIC_VMOVDQU) {
            tcg_out_vex_modrm_sib_offset(s, OPC_MOVDQU_WxVx + h.seg,
                                         TCG_TMP_VEC, 0,
                                         h.base, h.index, 0, h.ofs);
        } else {
            TCGLabel *l1 = gen_new_label();
            TCGLabel *l2 = gen_new_label();

            tcg_out_testi(s, h.base, 15);
            tcg_out_jxx(s, JCC_JNE, l1, true);

            tcg_out_vex_modrm_sib_offset(s, OPC_MOVDQA_WxVx + h.seg,
                                         TCG_TMP_VEC, 0,
                                         h.base, h.index, 0, h.ofs);
            tcg_out_jxx(s, JCC_JMP, l2, true);

            tcg_out_label(s, l1);
            tcg_out_vex_modrm_sib_offset(s, OPC_MOVDQU_WxVx + h.seg,
                                         TCG_TMP_VEC, 0,
                                         h.base, h.index, 0, h.ofs);
            tcg_out_label(s, l2);
        }
        break;

    default:
        g_assert_not_reached();
    }
}

static void tcg_out_qemu_st_taint(TCGContext *s, TCGReg datalo, TCGReg datahi,
                                   HostAddress h, MemOp memop)
{
    int movop = OPC_MOVL_EvGv;
    (void) datahi;
    /*
     * Do big-endian stores with movbe or system-mode.
     * User-only without movbe will have its swapping done generically.
     */
    if (memop & MO_BSWAP) {
        movop = OPC_MOVBE_MyGy;
    }

    switch (memop & MO_SIZE) {
    case MO_8:
        /* This is handled with constraints on INDEX_op_qemu_st8_i32. */
        tcg_debug_assert(TCG_TARGET_REG_BITS == 64 || datalo < 4);
        tcg_out_modrm_sib_offset(s, OPC_MOVB_EvGv + P_REXB_R + h.seg,
                                 datalo, h.sbase, h.sindex, 0, h.ofs);
        break;
    case MO_16:
        tcg_out_modrm_sib_offset(s, movop + P_DATA16 + h.seg, datalo,
                                 h.sbase, h.sindex, 0, h.ofs);
        break;
    case MO_32:
        tcg_out_modrm_sib_offset(s, movop + h.seg, datalo,
                                 h.sbase, h.sindex, 0, h.ofs);
        break;
    case MO_64:
        tcg_out_modrm_sib_offset(s, movop + P_REXW + h.seg, datalo,
                                    h.sbase, h.sindex, 0, h.ofs);
        break;

    default:
        g_assert_not_reached();
    }
}

static void tcg_out_qemu_st(TCGContext *s, TCGReg datalo, TCGReg datahi,
                            TCGReg addrlo, TCGReg addrhi,
                            MemOpIdx oi, TCGType data_type)
{
    TCGLabelQemuLdst *ldst;
    HostAddress h;
    tcg_insn_unit *je_label[2];

    tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP3, shadow_reg (datalo));
    tcg_out_cmp (s, TCG_REG_TEMP3, 0, 1, P_REXW);
    tcg_out8 (s, OPC_JCC_short + JCC_JE);
    je_label[0] = s->code_ptr;
    tcg_out8 (s, 0);
    tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP1, addrlo);
    tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP0, datalo);
    // buggy
    tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[0], TCG_REG_TEMP1); // address 
    tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[1], shadow_reg(datalo)); // taint
    tcg_out_mov(s, TCG_TYPE_I64, tcg_target_call_iarg_regs[2], datalo); // data
    tcg_out_mov(s, TCG_TYPE_PTR, tcg_target_call_iarg_regs[3], TCG_AREG0); // env
    tcg_out_branch(s, 1, (tcg_insn_unit *)taint_write_notify);
    tcg_out_zero_shadow_reg (s);
    tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (datalo), TCG_REG_TEMP3);
    tcg_out_mov (s, TCG_TYPE_I64, addrlo, TCG_REG_TEMP1);
    tcg_out_mov (s, TCG_TYPE_I64, datalo, TCG_REG_TEMP0);
    je_label[1] = s->code_ptr;
    tcg_patch8 (je_label[0], je_label[1] - je_label[0]-1);

    ldst = prepare_host_addr(s, &h, addrlo, addrhi, oi, false);
    tcg_out_qemu_st_direct(s, datalo, datahi, h, get_memop(oi));
    tcg_out_qemu_st_taint (s, TCG_REG_TEMP3, 0, h, get_memop(oi));


    if (ldst) {
        ldst->type = data_type;
        ldst->datalo_reg = datalo;
        ldst->datahi_reg = datahi;
        ldst->raddr = tcg_splitwx_to_rx(s->code_ptr);
    }
}

static void tcg_out_exit_tb(TCGContext *s, uintptr_t a0)
{
    /* Reuse the zeroing that exists for goto_ptr.  */
    if (a0 == 0) {
        tcg_out_jmp(s, tcg_code_gen_epilogue);
    } else {
        tcg_out_movi(s, TCG_TYPE_PTR, TCG_REG_EAX, a0);
        tcg_out_jmp(s, tb_ret_addr);
    }
}

static void tcg_out_goto_tb(TCGContext *s, int which)
{
    /*
     * Jump displacement must be aligned for atomic patching;
     * see if we need to add extra nops before jump
     */
    int gap = QEMU_ALIGN_PTR_UP(s->code_ptr + 1, 4) - s->code_ptr;
    if (gap != 1) {
        tcg_out_nopn(s, gap - 1);
    }
    tcg_out8(s, OPC_JMP_long); /* jmp im */
    set_jmp_insn_offset(s, which);
    tcg_out32(s, 0);
    set_jmp_reset_offset(s, which);
}

void tb_target_set_jmp_target(const TranslationBlock *tb, int n,
                              uintptr_t jmp_rx, uintptr_t jmp_rw)
{
    /* patch the branch destination */
    uintptr_t addr = tb->jmp_target_addr[n];
    qatomic_set((int32_t *)jmp_rw, addr - (jmp_rx + 4));
    /* no need to flush icache explicitly */
}

static void tcg_out_setcond32(TCGContext *s, TCGCond cond, TCGArg dest,
                              TCGArg arg1, TCGArg arg2, int const_arg2)
{
    tcg_out_cmp(s, arg1, arg2, const_arg2, 0);
    tcg_out_modrm(s, OPC_SETCC | tcg_cond_to_jcc[cond], 0, dest);
    tcg_out_ext8u(s, dest, dest);
}

static inline void tcg_out_op(TCGContext *s, TCGOpcode opc,
                              const TCGArg args[TCG_MAX_OP_ARGS],
                              const int const_args[TCG_MAX_OP_ARGS])
{
    TCGArg a0, a1, a2;
    int c, const_a2, rexw = 0, is64 = 0;
    tcg_insn_unit *j_label[2];
#if TCG_TARGET_REG_BITS == 64
# define OP_32_64(x) \
        case glue(glue(INDEX_op_, x), _i64): \
            rexw = P_REXW, is64 = 1; /* FALLTHRU */    \
        case glue(glue(INDEX_op_, x), _i32)
#else
# define OP_32_64(x) \
        case glue(glue(INDEX_op_, x), _i32)
#endif

    /* Hoist the loads of the most common arguments.  */
    a0 = args[0];
    a1 = args[1];
    a2 = args[2];
    const_a2 = const_args[2];

    switch (opc) {
    case INDEX_op_goto_ptr:
        /* jmp to the given host address (could be epilogue) */
        tcg_out_modrm(s, OPC_GRP5, EXT5_JMPN_Ev, a0);
        break;
    case INDEX_op_br:
        tcg_out_jxx(s, JCC_JMP, arg_label(a0), 0);
        break;
    OP_32_64(ld8u):
        /* Note that we can ignore REXW for the zero-extend to 64-bit.  */

        /* TAINT */
        tcg_out_modrm_offset(s, OPC_MOVZBL, TCG_REG_TEMP0, TCG_SHADOW_AREG0, a2);
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */

        tcg_out_modrm_offset(s, OPC_MOVZBL, a0, a1, a2);
        break;
    OP_32_64(ld8s):

        /* TAINT */
        tcg_out_modrm_offset(s, OPC_MOVZBL, TCG_REG_TEMP0, TCG_SHADOW_AREG0, a2);
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */

        tcg_out_modrm_offset(s, OPC_MOVSBL + rexw, a0, a1, a2);
        break;
    OP_32_64(ld16u):

        /* TAINT */
        tcg_out_modrm_offset(s, OPC_MOVZWL, TCG_REG_TEMP0, TCG_SHADOW_AREG0, a2);
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */

        /* Note that we can ignore REXW for the zero-extend to 64-bit.  */
        tcg_out_modrm_offset(s, OPC_MOVZWL, a0, a1, a2);
        break;
    OP_32_64(ld16s):

        /* TAINT */
        tcg_out_modrm_offset(s, OPC_MOVZWL, TCG_REG_TEMP0, TCG_SHADOW_AREG0, a2);
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */

        tcg_out_modrm_offset(s, OPC_MOVSWL + rexw, a0, a1, a2);
        break;
#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_ld32u_i64:
#endif
    case INDEX_op_ld_i32:
        
        /* TAINT */
        tcg_out_ld(s, TCG_TYPE_I32, shadow_reg(a0), TCG_SHADOW_AREG0, a2);
        /* END */

        tcg_out_ld(s, TCG_TYPE_I32, a0, a1, a2);
        break;

    OP_32_64(st8):
        if (const_args[0]) {
            tcg_out_modrm_offset(s, OPC_MOVB_EvIz, 0, a1, a2);
            tcg_out8(s, a0);
        } else {

            /* TAINT */
            tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP1, shadow_reg (a0));
            tcg_out_modrm_offset(s, OPC_MOVB_EvGv | P_REXB_R, TCG_REG_TEMP1, TCG_SHADOW_AREG0, a2);
            /* END */

            tcg_out_modrm_offset(s, OPC_MOVB_EvGv | P_REXB_R, a0, a1, a2);
        }
        break;
    OP_32_64(st16):
        if (const_args[0]) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvIz | P_DATA16, 0, a1, a2);
            tcg_out16(s, a0);
        } else {
            
            /* TAINT */
            tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP1, shadow_reg (a0));
            tcg_out_modrm_offset(s, OPC_MOVL_EvGv | P_DATA16, TCG_REG_TEMP1, TCG_SHADOW_AREG0, a2);
            /* END */

            tcg_out_modrm_offset(s, OPC_MOVL_EvGv | P_DATA16, a0, a1, a2);
        }
        break;
#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_st32_i64:
#endif
    case INDEX_op_st_i32:

        /* TAINT */
        tcg_out_st(s, TCG_TYPE_I32, shadow_reg(a0), TCG_SHADOW_AREG0, a2);
        /* END */

        tcg_out_st(s, TCG_TYPE_I32, a0, a1, a2);
        break;

    OP_32_64(add):
        c = ARITH_ADD;
        goto gen_arith;
    OP_32_64(sub):
        c = ARITH_SUB;
        goto gen_arith;
    OP_32_64(and):
        c = ARITH_AND;
        goto gen_arith;
    OP_32_64(or):
        c = ARITH_OR;
        goto gen_arith;
    OP_32_64(xor):
        c = ARITH_XOR;
        goto gen_arith;
    gen_arith:

        /* TAINT */
        tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (a2));
        /* END */
        tgen_arithr(s, c + rexw, a0, a2);
    
        break;

    OP_32_64(andc):

        /* TAINT */
        tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a2), shadow_reg (a1));
        /* END */

        tcg_out_vex_modrm(s, OPC_ANDN + rexw, a0, a2, a1);
        
        break;

    OP_32_64(mul):
        /* TAINT */
        tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (a2));
        if (is64) {
            tcg_out_union_vec_64 (s, shadow_reg (a0));
        } else {
            tcg_out_union_vec_32 (s, shadow_reg (a0));
        }
        /* END */

        tcg_out_modrm(s, OPC_IMUL_GvEv + rexw, a0, a2);
        break;

    OP_32_64(div2):

        /* TAINT */
        tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), shadow_reg (args[4]));
        tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RDX));
        if (is64) {
            tcg_out_union_vec_64 (s, shadow_reg (TCG_REG_RAX));
        } else {
            tcg_out_union_vec_32 (s, shadow_reg (TCG_REG_EAX));
        }
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (TCG_REG_RDX), shadow_reg (TCG_REG_RAX));
        /* END */

        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_IDIV, args[4]);
        break;
    OP_32_64(divu2):
    
        /* TAINT */
        tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), shadow_reg (args[4]));
        tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RDX));
        if (is64) {
            tcg_out_union_vec_64 (s, shadow_reg (TCG_REG_RAX));
        } else {
            tcg_out_union_vec_32 (s, shadow_reg (TCG_REG_EAX));
        }
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (TCG_REG_RDX), shadow_reg (TCG_REG_RAX));
        /* END */

        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_DIV, args[4]);
        break;

    OP_32_64(shl):
        /* For small constant 3-operand shift, use LEA.  */
        if (const_a2 && a0 != a1 && (a2 - 1) < 3) {
            if (a2 - 1 == 0) {
                /* shl $1,a1,a0 -> lea (a1,a1),a0 */
                tcg_out_modrm_sib_offset(s, OPC_LEA + rexw, a0, a1, a1, 0, 0);
            } else {
                /* shl $n,a1,a0 -> lea 0(,a1,n),a0 */
                tcg_out_modrm_sib_offset(s, OPC_LEA + rexw, a0, -1, a1, a2, 0);
            }
            break;
        }
        c = SHIFT_SHL;
        goto gen_shift;
    OP_32_64(shr):
        c = SHIFT_SHR;
        goto gen_shift;
    OP_32_64(sar):
        c = SHIFT_SAR;
        goto gen_shift;
    OP_32_64(rotl):
        c = SHIFT_ROL;
        goto gen_shift;
    OP_32_64(rotr):
        c = SHIFT_ROR;
        goto gen_shift;
    gen_shift:
        // /* TAINT */
        tcg_out_broadcast_vec (s, TCG_TYPE_I64, MO_8, shadow_reg (a2), shadow_reg (a2));
        tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (a2));
        // /* END */
        tcg_out_modrm(s, OPC_SHIFT_cl + rexw, c, a0);
        break;

    OP_32_64(ctz):

        /* TAINT */
        tcg_out_or_vec (s, TCG_SHADOW_TEMP0, shadow_reg (args[0]), shadow_reg (args[1]));
        tcg_out_or_vec (s, TCG_SHADOW_TEMP0, TCG_SHADOW_TEMP0, shadow_reg (args[2]));
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (args[0]), TCG_SHADOW_TEMP0);
        /* END */

        tcg_out_ctz(s, rexw, args[0], args[1], args[2], const_args[2]);
        break;
    OP_32_64(clz):

        /* TAINT */
        tcg_out_or_vec (s, TCG_SHADOW_TEMP0, shadow_reg (args[0]), shadow_reg (args[1]));
        tcg_out_or_vec (s, TCG_SHADOW_TEMP0, TCG_SHADOW_TEMP0, shadow_reg (args[2]));
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (args[0]), TCG_SHADOW_TEMP0);
        /* END */

        tcg_out_clz(s, rexw, args[0], args[1], args[2], const_args[2]);
        break;
    OP_32_64(ctpop):
        tcg_out_modrm(s, OPC_POPCNT + rexw, a0, a1);
        break;

    OP_32_64(brcond):
        tcg_out_brcond(s, rexw, a2, a0, a1, const_args[1],
                       arg_label(args[3]), 0);
        break;
    OP_32_64(setcond):
        /* TAINT */
        tcg_out_or_vec (s, shadow_reg(a0), shadow_reg(a1), shadow_reg(a2));
        /* END */

        tcg_out_setcond(s, rexw, args[3], a0, a1, a2, const_a2, false);
        break;
    OP_32_64(negsetcond):
        tcg_out_setcond(s, rexw, args[3], a0, a1, a2, const_a2, true);
        break;
    OP_32_64(movcond):
        /* TAINT */
        tcg_out_setcond32(s, args[5], TCG_REG_TEMP0, a1, a2, const_a2);
        tcg_out_cmp (s, TCG_REG_TEMP0, 0, 1, rexw);
        tcg_out8 (s, OPC_JCC_short + JCC_JE);
        j_label[0] = s->code_ptr;
        tcg_out8 (s, 0);
        tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (args[3]));
        /* taint ponter later */
        // tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (a1));
        // tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (a2));
        j_label[1] = s->code_ptr;
        tcg_patch8 (j_label[0], j_label[1] - j_label[0]-1);
        /* END */
        tcg_out_movcond(s, rexw, args[5], a0, a1, a2, const_a2, args[3]);
        break;

    OP_32_64(bswap16):
        if (a2 & TCG_BSWAP_OS) {
            /* Output must be sign-extended. */
            if (rexw) {
                /* TAINT */
                tcg_out_bswap64(s, TCG_REG_TEMP0);
                tcg_out_shifti(s, SHIFT_SAR + rexw, TCG_REG_TEMP0, 48);
                /* END */
                tcg_out_bswap64(s, a0);
                tcg_out_shifti(s, SHIFT_SAR + rexw, a0, 48);
            } else {
                /* TAINT */
                tcg_out_bswap32(s, TCG_REG_TEMP0);
                tcg_out_shifti(s, SHIFT_SAR, TCG_REG_TEMP0, 16);
                /* END */
                tcg_out_bswap32(s, a0);
                tcg_out_shifti(s, SHIFT_SAR, a0, 16);
            }
        } else if ((a2 & (TCG_BSWAP_IZ | TCG_BSWAP_OZ)) == TCG_BSWAP_OZ) {
            /* Output must be zero-extended, but input isn't. */
            /* TAINT */
            tcg_out_bswap32(s, TCG_REG_TEMP0);
            tcg_out_shifti(s, SHIFT_SHR, TCG_REG_TEMP0, 16);
            /* END */
            tcg_out_bswap32(s, a0);
            tcg_out_shifti(s, SHIFT_SHR, a0, 16);
        } else {
            /* TAINT */
            tcg_out_rolw_8(s, TCG_REG_TEMP0);
            /* END */
            tcg_out_rolw_8(s, a0);
        }
        /* TAINT */
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */
        break;
    OP_32_64(bswap32):

        tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP0, shadow_reg (a0));
        tcg_out_bswap32(s, TCG_REG_TEMP0);
        tcg_out_bswap32(s, a0);
        if (rexw && (a2 & TCG_BSWAP_OS)) {
            tcg_out_ext32s(s, TCG_REG_TEMP0, TCG_REG_TEMP0);
            tcg_out_ext32s(s, a0, a0);
        }
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        break;

    OP_32_64(neg):
        // SN: do nothing.
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_NEG, a0);
        break;
    OP_32_64(not):
        // SN: do nothing.
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_NOT, a0);
        break;

    case INDEX_op_qemu_ld_a64_i32:
        if (TCG_TARGET_REG_BITS == 32) {
            tcg_out_qemu_ld(s, a0, -1, a1, a2, args[3], TCG_TYPE_I32);
            break;
        }
        /* fall through */
    case INDEX_op_qemu_ld_a32_i32:
        tcg_out_qemu_ld(s, a0, -1, a1, -1, a2, TCG_TYPE_I32);
        break;
    case INDEX_op_qemu_ld_a32_i64:
        if (TCG_TARGET_REG_BITS == 64) {
            tcg_out_qemu_ld(s, a0, -1, a1, -1, a2, TCG_TYPE_I64);
        } else {
            tcg_out_qemu_ld(s, a0, a1, a2, -1, args[3], TCG_TYPE_I64);
        }
        break;
    case INDEX_op_qemu_ld_a64_i64:
        if (TCG_TARGET_REG_BITS == 64) {
            tcg_out_qemu_ld(s, a0, -1, a1, -1, a2, TCG_TYPE_I64);
        } else {
            tcg_out_qemu_ld(s, a0, a1, a2, args[3], args[4], TCG_TYPE_I64);
        }
        break;
    case INDEX_op_qemu_ld_a32_i128:
    case INDEX_op_qemu_ld_a64_i128:
        tcg_debug_assert(TCG_TARGET_REG_BITS == 64);
        tcg_out_qemu_ld(s, a0, a1, a2, -1, args[3], TCG_TYPE_I128);
        break;

    case INDEX_op_qemu_st_a64_i32:
    case INDEX_op_qemu_st8_a64_i32:
        if (TCG_TARGET_REG_BITS == 32) {
            tcg_out_qemu_st(s, a0, -1, a1, a2, args[3], TCG_TYPE_I32);
            break;
        }
        /* fall through */
    case INDEX_op_qemu_st_a32_i32:
    case INDEX_op_qemu_st8_a32_i32:
        tcg_out_qemu_st(s, a0, -1, a1, -1, a2, TCG_TYPE_I32);
        break;
    case INDEX_op_qemu_st_a32_i64:
        if (TCG_TARGET_REG_BITS == 64) {
            tcg_out_qemu_st(s, a0, -1, a1, -1, a2, TCG_TYPE_I64);
        } else {
            tcg_out_qemu_st(s, a0, a1, a2, -1, args[3], TCG_TYPE_I64);
        }
        break;
    case INDEX_op_qemu_st_a64_i64:
        if (TCG_TARGET_REG_BITS == 64) {
            tcg_out_qemu_st(s, a0, -1, a1, -1, a2, TCG_TYPE_I64);
        } else {
            tcg_out_qemu_st(s, a0, a1, a2, args[3], args[4], TCG_TYPE_I64);
        }
        break;
    case INDEX_op_qemu_st_a32_i128:
    case INDEX_op_qemu_st_a64_i128:
        tcg_debug_assert(TCG_TARGET_REG_BITS == 64);
        tcg_out_qemu_st(s, a0, a1, a2, -1, args[3], TCG_TYPE_I128);
        break;

    OP_32_64(mulu2):
        /* TAINT */
        tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), shadow_reg (args[3]));
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (TCG_REG_RDX), shadow_reg (TCG_REG_RAX));
        /* END */
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_MUL, args[3]);
        break;
    OP_32_64(muls2):
        /* TAINT */
        tcg_out_or_vec (s, shadow_reg (TCG_REG_RAX), shadow_reg (TCG_REG_RAX), shadow_reg (args[3]));
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (TCG_REG_RDX), shadow_reg (TCG_REG_RAX));
        /* END */
        tcg_out_modrm(s, OPC_GRP3_Ev + rexw, EXT3_IMUL, args[3]);
        break;
    OP_32_64(add2):
    /* TAINT */
        /* Constraint: O2_I4(r0, r1, 0, ra, r4, r5)
         * 
         */
        tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (args[4]));
        tcg_out_or_vec (s, shadow_reg (a1), shadow_reg (a1), shadow_reg (args[5]));
        tcg_out_or_vec (s, shadow_reg (a1), shadow_reg (a1), shadow_reg (TCG_REG_RAX));
        /* END */
        if (const_args[4]) {
            tgen_arithi(s, ARITH_ADD + rexw, a0, args[4], 1);
        } else {
            tgen_arithr(s, ARITH_ADD + rexw, a0, args[4]);
        }
        if (const_args[5]) {
            tgen_arithi(s, ARITH_ADC + rexw, a1, args[5], 1);
        } else {
            tgen_arithr(s, ARITH_ADC + rexw, a1, args[5]);
        }
        break;
    OP_32_64(sub2):
        /* TAINT */
        /* Constraint: O2_I4(r0, r1, 0, ra, r4, r5)
         * 
         */
        tcg_out_or_vec (s, shadow_reg (a0), shadow_reg (a0), shadow_reg (args[4]));
        tcg_out_or_vec (s, shadow_reg (a1), shadow_reg (a1), shadow_reg (args[5]));
        tcg_out_or_vec (s, shadow_reg (a1), shadow_reg (a1), shadow_reg (TCG_REG_RAX));
        /* END */
        if (const_args[4]) {
            tgen_arithi(s, ARITH_SUB + rexw, a0, args[4], 1);
        } else {
            tgen_arithr(s, ARITH_SUB + rexw, a0, args[4]);
        }
        if (const_args[5]) {
            tgen_arithi(s, ARITH_SBB + rexw, a1, args[5], 1);
        } else {
            tgen_arithr(s, ARITH_SBB + rexw, a1, args[5]);
        }
        break;

    case INDEX_op_ld32s_i64:
        /* TAINT */
        /* SN: do same thing to the shadow regs */
        tcg_out_modrm_offset(s, OPC_MOVSLQ, TCG_REG_TEMP0, TCG_SHADOW_AREG0, a2);
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */
        tcg_out_modrm_offset(s, OPC_MOVSLQ, a0, a1, a2);
        break;
    case INDEX_op_ld_i64:
        /* TAINT */
        /* SN: do same thing to the shadow regs */
        tcg_out_ld(s, TCG_TYPE_I64, shadow_reg (a0), TCG_SHADOW_AREG0, a2);
        /* END */
        tcg_out_ld(s, TCG_TYPE_I64, a0, a1, a2);
        break;
    case INDEX_op_st_i64:
        if (const_args[0]) {
            tcg_out_modrm_offset(s, OPC_MOVL_EvIz | P_REXW, 0, a1, a2);
            tcg_out32(s, a0);
        } else {
            tcg_out_st(s, TCG_TYPE_I64, a0, a1, a2);
            /* TAINT */
            /* SN: do same thing to the shadow regs */
            tcg_out_st(s, TCG_TYPE_I64, shadow_reg (a0), TCG_SHADOW_AREG0, a2);
            /* END */
        }
        break;

    case INDEX_op_bswap64_i64:
        /* TAINT */
        tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP0, shadow_reg (a0));
        tcg_out_bswap64(s, TCG_REG_TEMP0);
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */
        tcg_out_bswap64(s, a0);
        break;
    case INDEX_op_extrh_i64_i32:
        /* TAINT */
        tcg_out_mov (s, TCG_TYPE_I64, TCG_REG_TEMP0, shadow_reg (a0));
        tcg_out_shifti(s, SHIFT_SHR + P_REXW, TCG_REG_TEMP0, 32);
        tcg_out_mov (s, TCG_TYPE_I64, shadow_reg (a0), TCG_REG_TEMP0);
        /* END */
        tcg_out_shifti(s, SHIFT_SHR + P_REXW, a0, 32);
        break;

    case INDEX_op_mb:
        tcg_out_mb(s, a0);
        break;
    case INDEX_op_mov_i32:  /* Always emitted via tcg_out_mov.  */
    case INDEX_op_mov_i64:
    case INDEX_op_call:     /* Always emitted via tcg_out_call.  */
    case INDEX_op_exit_tb:  /* Always emitted via tcg_out_exit_tb.  */
    case INDEX_op_goto_tb:  /* Always emitted via tcg_out_goto_tb.  */
    case INDEX_op_ext8s_i32:  /* Always emitted via tcg_reg_alloc_op.  */
    case INDEX_op_ext8s_i64:
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext8u_i64:
    case INDEX_op_ext16s_i32:
    case INDEX_op_ext16s_i64:
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext16u_i64:
    case INDEX_op_ext32s_i64:
    case INDEX_op_ext32u_i64:
    case INDEX_op_ext_i32_i64:
    case INDEX_op_extu_i32_i64:
    case INDEX_op_extrl_i64_i32:
    default:
        g_assert_not_reached();
    }

#undef OP_32_64
}


static TCGConstraintSetIndex tcg_target_op_def(TCGOpcode op)
{
    switch (op) {
    case INDEX_op_goto_ptr:
        return C_O0_I1(r);

    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8u_i64:
    case INDEX_op_ld8s_i32:
    case INDEX_op_ld8s_i64:
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16u_i64:
    case INDEX_op_ld16s_i32:
    case INDEX_op_ld16s_i64:
    case INDEX_op_ld_i32:
    case INDEX_op_ld32u_i64:
    case INDEX_op_ld32s_i64:
    case INDEX_op_ld_i64:
        return C_O1_I1(r, r);

    case INDEX_op_st8_i32:
    case INDEX_op_st8_i64:
        return C_O0_I2(q, r);

    case INDEX_op_st16_i32:
    case INDEX_op_st16_i64:
    case INDEX_op_st_i32:
    case INDEX_op_st32_i64:
    case INDEX_op_st_i64:
        return C_O0_I2(r, r);

    case INDEX_op_add_i32:
    case INDEX_op_add_i64:
    case INDEX_op_sub_i32:
    case INDEX_op_sub_i64:
    case INDEX_op_mul_i32:
    case INDEX_op_mul_i64:
    case INDEX_op_or_i32:
    case INDEX_op_or_i64:
    case INDEX_op_xor_i32:
    case INDEX_op_xor_i64:
    case INDEX_op_and_i32:
    case INDEX_op_and_i64:
        return C_O1_I2(r, 0, r);

    case INDEX_op_andc_i32:
    case INDEX_op_andc_i64:
        return C_O1_I2(r, r, r);

    case INDEX_op_shl_i32:
    case INDEX_op_shl_i64:
    case INDEX_op_shr_i32:
    case INDEX_op_shr_i64:
    case INDEX_op_sar_i32:
    case INDEX_op_sar_i64:
    case INDEX_op_rotl_i32:
    case INDEX_op_rotl_i64:
    case INDEX_op_rotr_i32:
    case INDEX_op_rotr_i64:
    return C_O1_I2(r, 0, c);

    case INDEX_op_brcond_i32:
    case INDEX_op_brcond_i64:
        return C_O0_I2(r, re);

    case INDEX_op_bswap16_i32:
    case INDEX_op_bswap16_i64:
    case INDEX_op_bswap32_i32:
    case INDEX_op_bswap32_i64:
    case INDEX_op_bswap64_i64:
    case INDEX_op_neg_i32:
    case INDEX_op_neg_i64:
    case INDEX_op_not_i32:
    case INDEX_op_not_i64:
    case INDEX_op_extrh_i64_i32:
        return C_O1_I1(r, 0);

    case INDEX_op_ext8s_i32:
    case INDEX_op_ext8s_i64:
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext8u_i64:
        return C_O1_I1(r, q);

    case INDEX_op_ext16s_i32:
    case INDEX_op_ext16s_i64:
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext16u_i64:
    case INDEX_op_ext32s_i64:
    case INDEX_op_ext32u_i64:
    case INDEX_op_ext_i32_i64:
    case INDEX_op_extu_i32_i64:
    case INDEX_op_extrl_i64_i32:
    case INDEX_op_extract_i32:
    case INDEX_op_extract_i64:
    case INDEX_op_sextract_i32:
    case INDEX_op_ctpop_i32:
    case INDEX_op_ctpop_i64:
        return C_O1_I1(r, r);

    case INDEX_op_extract2_i32:
    case INDEX_op_extract2_i64:
        return C_O1_I2(r, 0, r);

    case INDEX_op_deposit_i32:
    case INDEX_op_deposit_i64:
        return C_O1_I2(q, 0, q);

    case INDEX_op_setcond_i32:
    case INDEX_op_setcond_i64:
    case INDEX_op_negsetcond_i32:
    case INDEX_op_negsetcond_i64:
        return C_O1_I2(q, r, r);

    case INDEX_op_movcond_i32:
    case INDEX_op_movcond_i64:
        return C_O1_I4(r, r, r, r, 0);

    case INDEX_op_div2_i32:
    case INDEX_op_div2_i64:
    case INDEX_op_divu2_i32:
    case INDEX_op_divu2_i64:
        return C_O2_I3(a, d, 0, 1, r);

    case INDEX_op_mulu2_i32:
    case INDEX_op_mulu2_i64:
    case INDEX_op_muls2_i32:
    case INDEX_op_muls2_i64:
        return C_O2_I2(a, d, a, r);

    case INDEX_op_add2_i32:
    case INDEX_op_add2_i64:
    case INDEX_op_sub2_i32:
    case INDEX_op_sub2_i64:
        return C_N1_O1_I4(r, r, 0, 1, r, r);

    case INDEX_op_ctz_i32:
    case INDEX_op_ctz_i64:
        return have_bmi1 ? C_N1_I2(r, r, r) : C_N1_I2(r, r, r);

    case INDEX_op_clz_i32:
    case INDEX_op_clz_i64:
        return have_lzcnt ? C_N1_I2(r, r, r) : C_N1_I2(r, r, r);

    case INDEX_op_qemu_ld_a32_i32:
        return C_O1_I1(r, L);
    case INDEX_op_qemu_ld_a64_i32:
        return TCG_TARGET_REG_BITS == 64 ? C_O1_I1(r, L) : C_O1_I2(r, L, L);

    case INDEX_op_qemu_st_a32_i32:
        return C_O0_I2(L, L);
    case INDEX_op_qemu_st_a64_i32:
        return TCG_TARGET_REG_BITS == 64 ? C_O0_I2(L, L) : C_O0_I3(L, L, L);
    case INDEX_op_qemu_st8_a32_i32:
        return C_O0_I2(s, L);
    case INDEX_op_qemu_st8_a64_i32:
        return TCG_TARGET_REG_BITS == 64 ? C_O0_I2(s, L) : C_O0_I3(s, L, L);

    case INDEX_op_qemu_ld_a32_i64:
        return TCG_TARGET_REG_BITS == 64 ? C_O1_I1(r, L) : C_O2_I1(r, r, L);
    case INDEX_op_qemu_ld_a64_i64:
        return TCG_TARGET_REG_BITS == 64 ? C_O1_I1(r, L) : C_O2_I2(r, r, L, L);

    case INDEX_op_qemu_st_a32_i64:
        return TCG_TARGET_REG_BITS == 64 ? C_O0_I2(L, L) : C_O0_I3(L, L, L);
    case INDEX_op_qemu_st_a64_i64:
        return TCG_TARGET_REG_BITS == 64 ? C_O0_I2(L, L) : C_O0_I4(L, L, L, L);

    case INDEX_op_qemu_ld_a32_i128:
    case INDEX_op_qemu_ld_a64_i128:
        tcg_debug_assert(TCG_TARGET_REG_BITS == 64);
        return C_O2_I1(r, r, L);
    case INDEX_op_qemu_st_a32_i128:
    case INDEX_op_qemu_st_a64_i128:
        tcg_debug_assert(TCG_TARGET_REG_BITS == 64);
        return C_O0_I3(L, L, L);

    case INDEX_op_brcond2_i32:
        return C_O0_I4(r, r, ri, ri);

    case INDEX_op_setcond2_i32:
        return C_O1_I4(r, r, r, ri, ri);
        
    default:
        g_assert_not_reached();
    }
}

static const int tcg_target_callee_save_regs[] = {
#if TCG_TARGET_REG_BITS == 64
    TCG_REG_RBP,
    TCG_REG_RBX,
#if defined(_WIN64)
    TCG_REG_RDI,
    TCG_REG_RSI,
#endif
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14, /* Currently used for the global env. */
    TCG_REG_R15,
#else
    TCG_REG_EBP, /* Currently used for the global env. */
    TCG_REG_EBX,
    TCG_REG_ESI,
    TCG_REG_EDI,
#endif
};

/* Compute frame size via macros, to share between tcg_target_qemu_prologue
   and tcg_register_jit.  */

#define SHADOW_REG_SAVE_SIZE 128

#define PUSH_SIZE \
    ((1 + ARRAY_SIZE(tcg_target_callee_save_regs)) \
     * (TCG_TARGET_REG_BITS / 8))

#define FRAME_SIZE \
    ((PUSH_SIZE \
      + TCG_STATIC_CALL_ARGS_SIZE \
      + CPU_TEMP_BUF_NLONGS * sizeof(long) \
      + SHADOW_REG_SAVE_SIZE \
      + TCG_TARGET_STACK_ALIGN - 1) \
     & ~(TCG_TARGET_STACK_ALIGN - 1))

static void tcg_out_save_shadow_reg (TCGContext *s) {
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM0, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 0);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM1, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 8);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM2, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 16);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM3, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 24);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM6, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 32);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM7, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 40);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM8, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 48);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM9, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 56);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM10, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 64);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM11, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 72);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM4, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 80);
    tcg_out_st (s, TCG_TYPE_I64, TCG_REG_XMM5, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 88);    
}

static void tcg_out_restore_shadow_reg (TCGContext *s) {
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM0, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 0);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM1, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 8);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM2, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 16);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM3, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 24);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM6, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 32);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM7, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 40);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM8, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 48);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM9, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 56);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM10, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 64);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM11, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 72);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM4, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 80);
    tcg_out_ld (s, TCG_TYPE_I64, TCG_REG_XMM5, TCG_REG_CALL_STACK, (PUSH_SIZE + TCG_STATIC_CALL_ARGS_SIZE + CPU_TEMP_BUF_NLONGS * sizeof(long)) + 88);
}

static void tcg_out_zero_shadow_reg (TCGContext *s) {
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM0, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM1, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM2, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM3, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM4, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM5, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM6, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM7, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM8, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM9, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM10, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM11, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM12, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM13, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM14, 0);
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_XMM15, 0);
}

/* Generate global QEMU prologue and epilogue code */
static void tcg_target_qemu_prologue(TCGContext *s)
{
    int i, stack_addend;

    /* TB prologue */

    /* Reserve some stack space, also for TCG temps.  */
    stack_addend = FRAME_SIZE - PUSH_SIZE;
    tcg_set_frame(s, TCG_REG_CALL_STACK, TCG_STATIC_CALL_ARGS_SIZE,
                  CPU_TEMP_BUF_NLONGS * sizeof(long));

    /* Save all callee saved registers.  */
    for (i = 0; i < ARRAY_SIZE(tcg_target_callee_save_regs); i++) {
        tcg_out_push(s, tcg_target_callee_save_regs[i]);
    }

    if (!tcg_use_softmmu && guest_base) {
        int seg = setup_guest_base_seg();
        if (seg != 0) {
            x86_guest_base.seg = seg;
        } else if (guest_base == (int32_t)guest_base) {
            x86_guest_base.ofs = guest_base;
        } else {
            assert(TCG_TARGET_REG_BITS == 64);
            /* Choose R12 because, as a base, it requires a SIB byte. */
            x86_guest_base.index = TCG_REG_R12;
            tcg_out_movi(s, TCG_TYPE_PTR, x86_guest_base.index, guest_base);
            tcg_regset_set_reg(s->reserved_regs, x86_guest_base.index);
        }
    }

    if (TCG_TARGET_REG_BITS == 32) {
        tcg_out_ld(s, TCG_TYPE_PTR, TCG_AREG0, TCG_REG_ESP,
                   (ARRAY_SIZE(tcg_target_callee_save_regs) + 1) * 4);
        tcg_out_addi(s, TCG_REG_ESP, -stack_addend);
        /* jmp *tb.  */
        tcg_out_modrm_offset(s, OPC_GRP5, EXT5_JMPN_Ev, TCG_REG_ESP,
                             (ARRAY_SIZE(tcg_target_callee_save_regs) + 2) * 4
                             + stack_addend);
    } else {
        tcg_out_mov(s, TCG_TYPE_PTR, TCG_AREG0, tcg_target_call_iarg_regs[0]);
        tcg_out_addi(s, TCG_REG_ESP, -stack_addend);

        tcg_out_mov(s, TCG_TYPE_PTR, TCG_SHADOW_AREG0, TCG_AREG0);
        tcg_out_mov(s, TCG_TYPE_PTR, TCG_SHADOW_STACK, TCG_AREG0);

        tcg_out_addi(s, TCG_SHADOW_AREG0, offsetof (CPUState, shadow_env) - sizeof (CPUState));
        tcg_out_addi(s, TCG_SHADOW_STACK, offsetof (CPUState, shadow_stack) - sizeof (CPUState) + SHADOW_STACKS_SIZE);
        tcg_out_addi(s, TCG_SHADOW_STACK, -stack_addend);
        tcg_out_zero_shadow_reg (s);
        /* jmp *tb.  */
        tcg_out_modrm(s, OPC_GRP5, EXT5_JMPN_Ev, tcg_target_call_iarg_regs[1]);
    }
    /*
     * Return path for goto_ptr. Set return value to 0, a-la exit_tb,
     * and fall through to the rest of the epilogue.
     */
    tcg_code_gen_epilogue = tcg_splitwx_to_rx(s->code_ptr);
    tcg_out_movi(s, TCG_TYPE_REG, TCG_REG_EAX, 0);

    /* TB epilogue */
    tb_ret_addr = tcg_splitwx_to_rx(s->code_ptr);

    tcg_out_addi(s, TCG_REG_CALL_STACK, stack_addend);

    if (have_avx2) {
        tcg_out_vex_opc(s, OPC_VZEROUPPER, 0, 0, 0, 0);
    }
    for (i = ARRAY_SIZE(tcg_target_callee_save_regs) - 1; i >= 0; i--) {
        tcg_out_pop(s, tcg_target_callee_save_regs[i]);
    }
    tcg_out_opc(s, OPC_RET, 0, 0, 0);
}

static void tcg_out_tb_start(TCGContext *s)
{
    /* nothing to do */
}

static void tcg_out_nop_fill(tcg_insn_unit *p, int count)
{
    memset(p, 0x90, count);
}

static void tcg_target_init(TCGContext *s)
{
    tcg_target_available_regs[TCG_TYPE_I32] = ALL_GENERAL_REGS;
    tcg_target_available_regs[TCG_TYPE_I64] = ALL_GENERAL_REGS;

    tcg_target_call_clobber_regs = ALL_VECTOR_REGS;
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_EAX);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_EDX);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_ECX);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_RDI);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_RSI);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R8);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R9);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R10);
    tcg_regset_set_reg(tcg_target_call_clobber_regs, TCG_REG_R11);

    s->reserved_regs = 0;
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_CALL_STACK);

    tcg_regset_set_reg(s->reserved_regs, TCG_REG_RBX);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_R12);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_R13);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_R14);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_R15);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM0);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM1);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM2);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM3);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM4);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM5);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM6);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM7);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM8);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM9);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM10);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM11);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM12);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM13);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM14);
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_XMM15);
}

typedef struct {
    DebugFrameHeader h;
    uint8_t fde_def_cfa[4];
    uint8_t fde_reg_ofs[14];
} DebugFrame;

/* We're expecting a 2 byte uleb128 encoded value.  */
QEMU_BUILD_BUG_ON(FRAME_SIZE >= (1 << 14));

#if !defined(__ELF__)
    /* Host machine without ELF. */
#elif TCG_TARGET_REG_BITS == 64
#define ELF_HOST_MACHINE EM_X86_64
static const DebugFrame debug_frame = {
    .h.cie.len = sizeof(DebugFrameCIE)-4, /* length after .len member */
    .h.cie.id = -1,
    .h.cie.version = 1,
    .h.cie.code_align = 1,
    .h.cie.data_align = 0x78,             /* sleb128 -8 */
    .h.cie.return_column = 16,

    /* Total FDE size does not include the "len" member.  */
    .h.fde.len = sizeof(DebugFrame) - offsetof(DebugFrame, h.fde.cie_offset),

    .fde_def_cfa = {
        12, 7,                          /* DW_CFA_def_cfa %rsp, ... */
        (FRAME_SIZE & 0x7f) | 0x80,     /* ... uleb128 FRAME_SIZE */
        (FRAME_SIZE >> 7)
    },
    .fde_reg_ofs = {
        0x90, 1,                        /* DW_CFA_offset, %rip, -8 */
        /* The following ordering must match tcg_target_callee_save_regs.  */
        0x86, 2,                        /* DW_CFA_offset, %rbp, -16 */
        0x83, 3,                        /* DW_CFA_offset, %rbx, -24 */
        0x8c, 4,                        /* DW_CFA_offset, %r12, -32 */
        0x8d, 5,                        /* DW_CFA_offset, %r13, -40 */
        0x8e, 6,                        /* DW_CFA_offset, %r14, -48 */
        0x8f, 7,                        /* DW_CFA_offset, %r15, -56 */
    }
};
#else
#define ELF_HOST_MACHINE EM_386
static const DebugFrame debug_frame = {
    .h.cie.len = sizeof(DebugFrameCIE)-4, /* length after .len member */
    .h.cie.id = -1,
    .h.cie.version = 1,
    .h.cie.code_align = 1,
    .h.cie.data_align = 0x7c,             /* sleb128 -4 */
    .h.cie.return_column = 8,

    /* Total FDE size does not include the "len" member.  */
    .h.fde.len = sizeof(DebugFrame) - offsetof(DebugFrame, h.fde.cie_offset),

    .fde_def_cfa = {
        12, 4,                          /* DW_CFA_def_cfa %esp, ... */
        (FRAME_SIZE & 0x7f) | 0x80,     /* ... uleb128 FRAME_SIZE */
        (FRAME_SIZE >> 7)
    },
    .fde_reg_ofs = {
        0x88, 1,                        /* DW_CFA_offset, %eip, -4 */
        /* The following ordering must match tcg_target_callee_save_regs.  */
        0x85, 2,                        /* DW_CFA_offset, %ebp, -8 */
        0x83, 3,                        /* DW_CFA_offset, %ebx, -12 */
        0x86, 4,                        /* DW_CFA_offset, %esi, -16 */
        0x87, 5,                        /* DW_CFA_offset, %edi, -20 */
    }
};
#endif

#if defined(ELF_HOST_MACHINE)
void tcg_register_jit(const void *buf, size_t buf_size)
{
    tcg_register_jit_int(buf, buf_size, &debug_frame, sizeof(debug_frame));
}
#endif
