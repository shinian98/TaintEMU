/**
 * do_ld_bytes_beN
 * @p: translation parameters
 * @ret_be: accumulated data
 *
 * Load @p->size bytes from @p->haddr, which is RAM.
 * The bytes to concatenated in big-endian order with @ret_be.
 */
static uint64_t do_ld_s_bytes_beN(MMULookupPageData *p, uint64_t ret_be)
{
    uint8_t *saddr = p->saddr;
    int i, size = p->size;

    for (i = 0; i < size; i++) {
        ret_be = (ret_be << 8) | saddr[i];
    }
    return ret_be;
}

/**
 * do_ld_parts_beN
 * @p: translation parameters
 * @ret_be: accumulated data
 *
 * As do_ld_bytes_beN, but atomically on each aligned part.
 */
static uint64_t do_ld_s_parts_beN(MMULookupPageData *p, uint64_t ret_be)
{
    void *saddr = p->saddr;
    int size = p->size;

    do {
        uint64_t x;
        int n;

        /*
         * Find minimum of alignment and size.
         * This is slightly stronger than required by MO_ATOM_SUBALIGN, which
         * would have only checked the low bits of addr|size once at the start,
         * but is just as easy.
         */
        switch (((uintptr_t)saddr | size) & 7) {
        case 4:
            x = cpu_to_be32(load_atomic4(saddr));
            ret_be = (ret_be << 32) | x;
            n = 4;
            break;
        case 2:
        case 6:
            x = cpu_to_be16(load_atomic2(saddr));
            ret_be = (ret_be << 16) | x;
            n = 2;
            break;
        default:
            x = *(uint8_t *)saddr;
            ret_be = (ret_be << 8) | x;
            n = 1;
            break;
        case 0:
            g_assert_not_reached();
        }
        saddr += n;
        size -= n;
    } while (size != 0);
    return ret_be;
}

/**
 * do_ld_parts_be4
 * @p: translation parameters
 * @ret_be: accumulated data
 *
 * As do_ld_bytes_beN, but with one atomic load.
 * Four aligned bytes are guaranteed to cover the load.
 */
static uint64_t do_ld_s_whole_be4(MMULookupPageData *p, uint64_t ret_be)
{
    int o = p->addr & 3;
    uint32_t x = load_atomic4(p->saddr - o);

    x = cpu_to_be32(x);
    x <<= o * 8;
    x >>= (4 - p->size) * 8;
    return (ret_be << (p->size * 8)) | x;
}

/**
 * do_ld_parts_be8
 * @p: translation parameters
 * @ret_be: accumulated data
 *
 * As do_ld_bytes_beN, but with one atomic load.
 * Eight aligned bytes are guaranteed to cover the load.
 */
static uint64_t do_ld_s_whole_be8(CPUState *cpu, uintptr_t ra,
                                MMULookupPageData *p, uint64_t ret_be)
{
    int o = p->addr & 7;
    uint64_t x = load_atomic8_or_exit(cpu, ra, p->saddr - o);

    x = cpu_to_be64(x);
    x <<= o * 8;
    x >>= (8 - p->size) * 8;
    return (ret_be << (p->size * 8)) | x;
}

/**
 * do_ld_parts_be16
 * @p: translation parameters
 * @ret_be: accumulated data
 *
 * As do_ld_bytes_beN, but with one atomic load.
 * 16 aligned bytes are guaranteed to cover the load.
 */
static Int128 do_ld_s_whole_be16(CPUState *cpu, uintptr_t ra,
                               MMULookupPageData *p, uint64_t ret_be)
{
    int o = p->addr & 15;
    Int128 x, y = load_atomic16_or_exit(cpu, ra, p->saddr - o);
    int size = p->size;

    if (!HOST_BIG_ENDIAN) {
        y = bswap128(y);
    }
    y = int128_lshift(y, o * 8);
    y = int128_urshift(y, (16 - size) * 8);
    x = int128_make64(ret_be);
    x = int128_lshift(x, size * 8);
    return int128_or(x, y);
}

/*
 * Wrapper for the above.
 */
static uint64_t do_ld_s_beN(CPUState *cpu, MMULookupPageData *p,
                          uint64_t ret_be, int mmu_idx, MMUAccessType type,
                          MemOp mop, uintptr_t ra)
{
    MemOp atom;
    unsigned tmp, half_size;

    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    }

    /*
     * It is a given that we cross a page and therefore there is no
     * atomicity for the load as a whole, but subobjects may need attention.
     */
    atom = mop & MO_ATOM_MASK;
    switch (atom) {
    case MO_ATOM_SUBALIGN:
        return do_ld_s_parts_beN(p, ret_be);

    case MO_ATOM_IFALIGN_PAIR:
    case MO_ATOM_WITHIN16_PAIR:
        tmp = mop & MO_SIZE;
        tmp = tmp ? tmp - 1 : 0;
        half_size = 1 << tmp;
        if (atom == MO_ATOM_IFALIGN_PAIR
            ? p->size == half_size
            : p->size >= half_size) {
            if (!HAVE_al8_fast && p->size < 4) {
                return do_ld_s_whole_be4(p, ret_be);
            } else {
                return do_ld_s_whole_be8(cpu, ra, p, ret_be);
            }
        }
        /* fall through */

    case MO_ATOM_IFALIGN:
    case MO_ATOM_WITHIN16:
    case MO_ATOM_NONE:
        return do_ld_s_bytes_beN(p, ret_be);

    default:
        g_assert_not_reached();
    }
}

/*
 * Wrapper for the above, for 8 < size < 16.
 */
static Int128 do_ld16_s_beN(CPUState *cpu, MMULookupPageData *p,
                          uint64_t a, int mmu_idx, MemOp mop, uintptr_t ra)
{
    int size = p->size;
    uint64_t b;
    MemOp atom;

    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    }

    /*
     * It is a given that we cross a page and therefore there is no
     * atomicity for the load as a whole, but subobjects may need attention.
     */
    atom = mop & MO_ATOM_MASK;
    switch (atom) {
    case MO_ATOM_SUBALIGN:
        p->size = size - 8;
        a = do_ld_s_parts_beN(p, a);
        p->saddr += size - 8;
        p->size = 8;
        b = do_ld_s_parts_beN(p, 0);
        break;

    case MO_ATOM_WITHIN16_PAIR:
        /* Since size > 8, this is the half that must be atomic. */
        return do_ld_s_whole_be16(cpu, ra, p, a);

    case MO_ATOM_IFALIGN_PAIR:
        /*
         * Since size > 8, both halves are misaligned,
         * and so neither is atomic.
         */
    case MO_ATOM_IFALIGN:
    case MO_ATOM_WITHIN16:
    case MO_ATOM_NONE:
        p->size = size - 8;
        a = do_ld_s_bytes_beN(p, a);
        b = ldq_be_p(p->saddr + size - 8);
        break;

    default:
        g_assert_not_reached();
    }

    return int128_make128(b, a);
}

static uint8_t do_ld_s_1(CPUState *cpu, MMULookupPageData *p, int mmu_idx,
                       MMUAccessType type, uintptr_t ra)
{
    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    } else {
        return *(uint8_t *)p->saddr;
    }
}

static uint16_t do_ld_s_2(CPUState *cpu, MMULookupPageData *p, int mmu_idx,
                        MMUAccessType type, MemOp memop, uintptr_t ra)
{
    uint16_t ret;

    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    } else {
        /* Perform the load host endian, then swap if necessary. */
        ret = load_atom_2(cpu, ra, p->saddr, memop);
        if (memop & MO_BSWAP) {
            ret = bswap16(ret);
        }
    }
    return ret;
}

static uint32_t do_ld_s_4(CPUState *cpu, MMULookupPageData *p, int mmu_idx,
                        MMUAccessType type, MemOp memop, uintptr_t ra)
{
    uint32_t ret;

    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    } else {
        /* Perform the load host endian. */
        ret = load_atom_4(cpu, ra, p->saddr, memop);
        if (memop & MO_BSWAP) {
            ret = bswap32(ret);
        }
    }
    return ret;
}

static uint64_t do_ld_s_8(CPUState *cpu, MMULookupPageData *p, int mmu_idx,
                        MMUAccessType type, MemOp memop, uintptr_t ra)
{
    uint64_t ret;

    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    } else {
        /* Perform the load host endian. */
        ret = load_atom_8(cpu, ra, p->saddr, memop);
        if (memop & MO_BSWAP) {
            ret = bswap64(ret);
        }
    }
    return ret;
}


/*
 * Wrapper for store ops.
 */
static uint64_t do_st_s_leN(CPUState *cpu, MMULookupPageData *p,
                          uint64_t val_le, int mmu_idx,
                          MemOp mop, uintptr_t ra)
{
    MemOp atom;
    unsigned tmp, half_size;

    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    } else if (unlikely(p->flags & TLB_DISCARD_WRITE)) {
        return val_le >> (p->size * 8);
    }

    /*
     * It is a given that we cross a page and therefore there is no atomicity
     * for the store as a whole, but subobjects may need attention.
     */
    atom = mop & MO_ATOM_MASK;
    switch (atom) {
    case MO_ATOM_SUBALIGN:
        return store_parts_leN(p->saddr, p->size, val_le);

    case MO_ATOM_IFALIGN_PAIR:
    case MO_ATOM_WITHIN16_PAIR:
        tmp = mop & MO_SIZE;
        tmp = tmp ? tmp - 1 : 0;
        half_size = 1 << tmp;
        if (atom == MO_ATOM_IFALIGN_PAIR
            ? p->size == half_size
            : p->size >= half_size) {
            if (!HAVE_al8_fast && p->size <= 4) {
                return store_whole_le4(p->saddr, p->size, val_le);
            } else if (HAVE_al8) {
                return store_whole_le8(p->saddr, p->size, val_le);
            } else {
                cpu_loop_exit_atomic(cpu, ra);
            }
        }
        /* fall through */

    case MO_ATOM_IFALIGN:
    case MO_ATOM_WITHIN16:
    case MO_ATOM_NONE:
        return store_bytes_leN(p->saddr, p->size, val_le);

    default:
        g_assert_not_reached();
    }
}

/*
 * Wrapper for the above, for 8 < size < 16.
 */
static uint64_t do_st16_s_leN(CPUState *cpu, MMULookupPageData *p,
                            Int128 val_le, int mmu_idx,
                            MemOp mop, uintptr_t ra)
{
    int size = p->size;
    MemOp atom;

    if (unlikely(p->flags & TLB_MMIO)) {
        return 0;
    } else if (unlikely(p->flags & TLB_DISCARD_WRITE)) {
        return int128_gethi(val_le) >> ((size - 8) * 8);
    }

    /*
     * It is a given that we cross a page and therefore there is no atomicity
     * for the store as a whole, but subobjects may need attention.
     */
    atom = mop & MO_ATOM_MASK;
    switch (atom) {
    case MO_ATOM_SUBALIGN:
        store_parts_leN(p->saddr, 8, int128_getlo(val_le));
        return store_parts_leN(p->saddr + 8, p->size - 8,
                               int128_gethi(val_le));

    case MO_ATOM_WITHIN16_PAIR:
        /* Since size > 8, this is the half that must be atomic. */
        if (!HAVE_CMPXCHG128) {
            cpu_loop_exit_atomic(cpu, ra);
        }
        return store_whole_le16(p->saddr, p->size, val_le);

    case MO_ATOM_IFALIGN_PAIR:
        /*
         * Since size > 8, both halves are misaligned,
         * and so neither is atomic.
         */
    case MO_ATOM_IFALIGN:
    case MO_ATOM_WITHIN16:
    case MO_ATOM_NONE:
        stq_le_p(p->saddr, int128_getlo(val_le));
        return store_bytes_leN(p->saddr + 8, p->size - 8,
                               int128_gethi(val_le));

    default:
        g_assert_not_reached();
    }
}

static void do_st_s_1(CPUState *cpu, MMULookupPageData *p, uint8_t val,
                    int mmu_idx, uintptr_t ra)
{
    if (unlikely(p->flags & TLB_MMIO)) {
        return;
    } else if (unlikely(p->flags & TLB_DISCARD_WRITE)) {
        /* nothing */
    } else {
        *(uint8_t *)p->saddr = val;
    }
}

static void do_st_s_2(CPUState *cpu, MMULookupPageData *p, uint16_t val,
                    int mmu_idx, MemOp memop, uintptr_t ra)
{
    if (unlikely(p->flags & TLB_MMIO)) {
        return;
    } else if (unlikely(p->flags & TLB_DISCARD_WRITE)) {
        /* nothing */
    } else {
        /* Swap to host endian if necessary, then store. */
        if (memop & MO_BSWAP) {
            val = bswap16(val);
        }
        store_atom_2(cpu, ra, p->saddr, memop, val);
    }
}

static void do_st_s_4(CPUState *cpu, MMULookupPageData *p, uint32_t val,
                    int mmu_idx, MemOp memop, uintptr_t ra)
{
    if (unlikely(p->flags & TLB_MMIO)) {
        return;
    } else if (unlikely(p->flags & TLB_DISCARD_WRITE)) {
        /* nothing */
    } else {
        /* Swap to host endian if necessary, then store. */
        if (memop & MO_BSWAP) {
            val = bswap32(val);
        }
        store_atom_4(cpu, ra, p->saddr, memop, val);
    }
}

static void do_st_s_8(CPUState *cpu, MMULookupPageData *p, uint64_t val,
                    int mmu_idx, MemOp memop, uintptr_t ra)
{
    if (unlikely(p->flags & TLB_MMIO)) {
        return;
    } else if (unlikely(p->flags & TLB_DISCARD_WRITE)) {
        /* nothing */
    } else {
        /* Swap to host endian if necessary, then store. */
        if (memop & MO_BSWAP) {
            val = bswap64(val);
        }
        store_atom_8(cpu, ra, p->saddr, memop, val);
    }
}


static uint8_t do_ld1_shadow(CPUState *cpu, vaddr addr, MemOpIdx oi,
                          uintptr_t ra, MMUAccessType access_type)
{
    MMULookupLocals l;
    bool crosspage;

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    crosspage = mmu_lookup(cpu, addr, oi, ra, access_type, &l);
    tcg_debug_assert(!crosspage);

    return do_ld_s_1(cpu, &l.page[0], l.mmu_idx, access_type, ra);
}

static uint16_t do_ld2_shadow(CPUState *cpu, vaddr addr, MemOpIdx oi,
                           uintptr_t ra, MMUAccessType access_type)
{
    MMULookupLocals l;
    bool crosspage;
    uint16_t ret;
    uint8_t a, b;

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    crosspage = mmu_lookup(cpu, addr, oi, ra, access_type, &l);
    if (likely(!crosspage)) {
        return do_ld_s_2(cpu, &l.page[0], l.mmu_idx, access_type, l.memop, ra);
    }

    a = do_ld_s_1(cpu, &l.page[0], l.mmu_idx, access_type, ra);
    b = do_ld_s_1(cpu, &l.page[1], l.mmu_idx, access_type, ra);

    if ((l.memop & MO_BSWAP) == MO_LE) {
        ret = a | (b << 8);
    } else {
        ret = b | (a << 8);
    }
    return ret;
}

static uint32_t do_ld4_shadow(CPUState *cpu, vaddr addr, MemOpIdx oi,
                           uintptr_t ra, MMUAccessType access_type)
{
    MMULookupLocals l;
    bool crosspage;
    uint32_t ret;

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    crosspage = mmu_lookup(cpu, addr, oi, ra, access_type, &l);
    if (likely(!crosspage)) {
        return do_ld_s_4(cpu, &l.page[0], l.mmu_idx, access_type, l.memop, ra);
    }

    ret = do_ld_s_beN(cpu, &l.page[0], 0, l.mmu_idx, access_type, l.memop, ra);
    ret = do_ld_s_beN(cpu, &l.page[1], ret, l.mmu_idx, access_type, l.memop, ra);
    if ((l.memop & MO_BSWAP) == MO_LE) {
        ret = bswap32(ret);
    }
    return ret;
}

static uint64_t do_ld8_shadow (CPUState *cpu, vaddr addr, MemOpIdx oi,
                           uintptr_t ra, MMUAccessType access_type)
{
    MMULookupLocals l;
    bool crosspage;
    uint64_t ret;

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    crosspage = mmu_lookup(cpu, addr, oi, ra, access_type, &l);
    if (likely(!crosspage)) {
        return do_ld_s_8(cpu, &l.page[0], l.mmu_idx, access_type, l.memop, ra);
    }

    ret = do_ld_s_beN(cpu, &l.page[0], 0, l.mmu_idx, access_type, l.memop, ra);
    ret = do_ld_s_beN(cpu, &l.page[1], ret, l.mmu_idx, access_type, l.memop, ra);
    if ((l.memop & MO_BSWAP) == MO_LE) {
        ret = bswap64(ret);
    }
    return ret;
}

static Int128 do_ld16_shadow(CPUState *cpu, vaddr addr,
                          MemOpIdx oi, uintptr_t ra)
{
    MMULookupLocals l;
    bool crosspage;
    uint64_t a, b;
    Int128 ret;
    int first;

    cpu_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
    crosspage = mmu_lookup(cpu, addr, oi, ra, MMU_DATA_LOAD, &l);
    if (likely(!crosspage)) {
        if (unlikely(l.page[0].flags & TLB_MMIO)) {
            return int128_make128(0, 0); 
        } else {
            /* Perform the load host endian. */
            ret = load_atom_16(cpu, ra, l.page[0].saddr, l.memop);
            if (l.memop & MO_BSWAP) {
                ret = bswap128(ret);
            }
        }
        return ret;
    }

    first = l.page[0].size;
    if (first == 8) {
        MemOp mop8 = (l.memop & ~MO_SIZE) | MO_64;

        a = do_ld_s_8(cpu, &l.page[0], l.mmu_idx, MMU_DATA_LOAD, mop8, ra);
        b = do_ld_s_8(cpu, &l.page[1], l.mmu_idx, MMU_DATA_LOAD, mop8, ra);
        if ((mop8 & MO_BSWAP) == MO_LE) {
            ret = int128_make128(a, b);
        } else {
            ret = int128_make128(b, a);
        }
        return ret;
    }

    if (first < 8) {
        a = do_ld_s_beN(cpu, &l.page[0], 0, l.mmu_idx,
                      MMU_DATA_LOAD, l.memop, ra);
        ret = do_ld16_s_beN(cpu, &l.page[1], a, l.mmu_idx, l.memop, ra);
    } else {
        ret = do_ld16_s_beN(cpu, &l.page[0], 0, l.mmu_idx, l.memop, ra);
        b = int128_getlo(ret);
        ret = int128_lshift(ret, l.page[1].size * 8);
        a = int128_gethi(ret);
        b = do_ld_s_beN(cpu, &l.page[1], b, l.mmu_idx,
                      MMU_DATA_LOAD, l.memop, ra);
        ret = int128_make128(b, a);
    }
    if ((l.memop & MO_BSWAP) == MO_LE) {
        ret = bswap128(ret);
    }
    return ret;
}

static void do_st1_shadow(CPUState *cpu, vaddr addr, uint8_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    MMULookupLocals l;
    bool crosspage;

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    crosspage = mmu_lookup(cpu, addr, oi, ra, MMU_DATA_STORE, &l);
    tcg_debug_assert(!crosspage);

    do_st_s_1(cpu, &l.page[0], val, l.mmu_idx, ra);
}

static void do_st2_shadow(CPUState *cpu, vaddr addr, uint16_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    MMULookupLocals l;
    bool crosspage;
    uint8_t a, b;

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    crosspage = mmu_lookup(cpu, addr, oi, ra, MMU_DATA_STORE, &l);
    if (likely(!crosspage)) {
        do_st_s_2(cpu, &l.page[0], val, l.mmu_idx, l.memop, ra);
        return;
    }

    if ((l.memop & MO_BSWAP) == MO_LE) {
        a = val, b = val >> 8;
    } else {
        b = val, a = val >> 8;
    }
    do_st_s_1(cpu, &l.page[0], a, l.mmu_idx, ra);
    do_st_s_1(cpu, &l.page[1], b, l.mmu_idx, ra);
}

static void do_st4_shadow(CPUState *cpu, vaddr addr, uint32_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    MMULookupLocals l;
    bool crosspage;

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    crosspage = mmu_lookup(cpu, addr, oi, ra, MMU_DATA_STORE, &l);
    if (likely(!crosspage)) {
        do_st_s_4(cpu, &l.page[0], val, l.mmu_idx, l.memop, ra);
        return;
    }

    /* Swap to little endian for simplicity, then store by bytes. */
    if ((l.memop & MO_BSWAP) != MO_LE) {
        val = bswap32(val);
    }
    val = do_st_s_leN(cpu, &l.page[0], val, l.mmu_idx, l.memop, ra);
    (void) do_st_s_leN(cpu, &l.page[1], val, l.mmu_idx, l.memop, ra);
}

static void do_st8_shadow(CPUState *cpu, vaddr addr, uint64_t val,
                       MemOpIdx oi, uintptr_t ra)
{
    MMULookupLocals l;
    bool crosspage;

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    crosspage = mmu_lookup(cpu, addr, oi, ra, MMU_DATA_STORE, &l);
    if (likely(!crosspage)) {
        do_st_s_8(cpu, &l.page[0], val, l.mmu_idx, l.memop, ra);
        return;
    }

    /* Swap to little endian for simplicity, then store by bytes. */
    if ((l.memop & MO_BSWAP) != MO_LE) {
        val = bswap64(val);
    }
    val = do_st_s_leN(cpu, &l.page[0], val, l.mmu_idx, l.memop, ra);
    (void) do_st_s_leN(cpu, &l.page[1], val, l.mmu_idx, l.memop, ra);
}

static void do_st16_shadow(CPUState *cpu, vaddr addr, Int128 val,
                        MemOpIdx oi, uintptr_t ra)
{
    MMULookupLocals l;
    bool crosspage;
    uint64_t a, b;
    int first;

    cpu_req_mo(TCG_MO_LD_ST | TCG_MO_ST_ST);
    crosspage = mmu_lookup(cpu, addr, oi, ra, MMU_DATA_STORE, &l);
    if (likely(!crosspage)) {
        if (unlikely(l.page[0].flags & TLB_MMIO)) {
            return;
        } else if (unlikely(l.page[0].flags & TLB_DISCARD_WRITE)) {
            /* nothing */
        } else {
            /* Swap to host endian if necessary, then store. */
            if (l.memop & MO_BSWAP) {
                val = bswap128(val);
            }
            store_atom_16(cpu, ra, l.page[0].saddr, l.memop, val);
        }
        return;
    }

    first = l.page[0].size;
    if (first == 8) {
        MemOp mop8 = (l.memop & ~(MO_SIZE | MO_BSWAP)) | MO_64;

        if (l.memop & MO_BSWAP) {
            val = bswap128(val);
        }
        if (HOST_BIG_ENDIAN) {
            b = int128_getlo(val), a = int128_gethi(val);
        } else {
            a = int128_getlo(val), b = int128_gethi(val);
        }
        do_st_s_8(cpu, &l.page[0], a, l.mmu_idx, mop8, ra);
        do_st_s_8(cpu, &l.page[1], b, l.mmu_idx, mop8, ra);
        return;
    }

    if ((l.memop & MO_BSWAP) != MO_LE) {
        val = bswap128(val);
    }
    if (first < 8) {
        do_st_s_leN(cpu, &l.page[0], int128_getlo(val), l.mmu_idx, l.memop, ra);
        val = int128_urshift(val, first * 8);
        do_st16_s_leN(cpu, &l.page[1], val, l.mmu_idx, l.memop, ra);
    } else {
        b = do_st16_s_leN(cpu, &l.page[0], val, l.mmu_idx, l.memop, ra);
        do_st_s_leN(cpu, &l.page[1], b, l.mmu_idx, l.memop, ra);
    }
}

uint8_t cpu_ldb_shadow(CPUArchState *env, abi_ptr addr, MemOpIdx oi, uintptr_t ra)
{
    uint8_t ret;

    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_UB);
    ret = do_ld1_shadow(env_cpu(env), addr, oi, ra, MMU_DATA_LOAD);
    return ret;
}

uint16_t cpu_ldw_shadow(CPUArchState *env, abi_ptr addr,
                     MemOpIdx oi, uintptr_t ra)
{
    uint16_t ret;

    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_16);
    ret = do_ld2_shadow(env_cpu(env), addr, oi, ra, MMU_DATA_LOAD);
    return ret;
}

uint32_t cpu_ldl_shadow(CPUArchState *env, abi_ptr addr,
                     MemOpIdx oi, uintptr_t ra)
{
    uint32_t ret;

    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_32);
    ret = do_ld4_shadow(env_cpu(env), addr, oi, ra, MMU_DATA_LOAD);
    return ret;
}

uint64_t cpu_ldq_shadow(CPUArchState *env, abi_ptr addr,
                     MemOpIdx oi, uintptr_t ra)
{
    uint64_t ret;

    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_64);
    ret = do_ld8_shadow(env_cpu(env), addr, oi, ra, MMU_DATA_LOAD);
    return ret;
}

Int128 cpu_ld16_shadow(CPUArchState *env, abi_ptr addr,
                    MemOpIdx oi, uintptr_t ra)
{
    Int128 ret;

    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_128);
    ret = do_ld16_shadow(env_cpu(env), addr, oi, ra);
    return ret;
}

static void helper_stb_shadow(CPUArchState *env, uint64_t addr, uint32_t val,
                    MemOpIdx oi, uintptr_t ra)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_8);
    do_st1_shadow(env_cpu(env), addr, val, oi, ra);
}

void cpu_stb_shadow(CPUArchState *env, abi_ptr addr, uint8_t val,
                 MemOpIdx oi, uintptr_t retaddr)
{
    helper_stb_shadow(env, addr, val, oi, retaddr);
}

void cpu_stw_shadow(CPUArchState *env, abi_ptr addr, uint16_t val,
                 MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_16);
    do_st2_shadow(env_cpu(env), addr, val, oi, retaddr);
}

void cpu_stl_shadow(CPUArchState *env, abi_ptr addr, uint32_t val,
                    MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_32);
    do_st4_shadow(env_cpu(env), addr, val, oi, retaddr);
}

void cpu_stq_shadow(CPUArchState *env, abi_ptr addr, uint64_t val,
                 MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_64);
    do_st8_shadow(env_cpu(env), addr, val, oi, retaddr);
}

void cpu_st16_shadow(CPUArchState *env, abi_ptr addr, Int128 val,
                  MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_128);
    do_st16_shadow(env_cpu(env), addr, val, oi, retaddr);
}

/*
 * Wrappers of the above
 */

uint32_t cpu_ldub_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                            int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);
    return cpu_ldb_shadow(env, addr, oi, ra);
}

int cpu_ldsb_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                       int mmu_idx, uintptr_t ra)
{
    return (int8_t)cpu_ldub_shadow_mmuidx_ra(env, addr, mmu_idx, ra);
}

uint32_t cpu_lduw_be_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                               int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_BEUW | MO_UNALN, mmu_idx);
    return cpu_ldw_shadow(env, addr, oi, ra);
}

int cpu_ldsw_be_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                          int mmu_idx, uintptr_t ra)
{
    return (int16_t)cpu_lduw_be_shadow_mmuidx_ra(env, addr, mmu_idx, ra);
}

uint32_t cpu_ldl_be_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                              int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_BEUL | MO_UNALN, mmu_idx);
    return cpu_ldl_shadow(env, addr, oi, ra);
}

uint64_t cpu_ldq_be_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                              int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_BEUQ | MO_UNALN, mmu_idx);
    return cpu_ldq_shadow(env, addr, oi, ra);
}

uint32_t cpu_lduw_le_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                               int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_LEUW | MO_UNALN, mmu_idx);
    return cpu_ldw_shadow(env, addr, oi, ra);
}

int cpu_ldsw_le_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                          int mmu_idx, uintptr_t ra)
{
    return (int16_t)cpu_lduw_le_mmuidx_ra(env, addr, mmu_idx, ra);
}

uint32_t cpu_ldl_le_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                              int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_LEUL | MO_UNALN, mmu_idx);
    return cpu_ldl_shadow(env, addr, oi, ra);
}

uint64_t cpu_ldq_le_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr,
                              int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_LEUQ | MO_UNALN, mmu_idx);
    return cpu_ldq_shadow(env, addr, oi, ra);
}

void cpu_stb_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr, uint32_t val,
                       int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);
    cpu_stb_shadow(env, addr, val, oi, ra);
}

void cpu_stw_be_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr, uint32_t val,
                          int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_BEUW | MO_UNALN, mmu_idx);
    cpu_stw_shadow(env, addr, val, oi, ra);
}

void cpu_stl_be_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr, uint32_t val,
                          int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_BEUL | MO_UNALN, mmu_idx);
    cpu_stl_shadow(env, addr, val, oi, ra);
}

void cpu_stq_be_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr, uint64_t val,
                          int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_BEUQ | MO_UNALN, mmu_idx);
    cpu_stq_shadow(env, addr, val, oi, ra);
}

void cpu_stw_le_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr, uint32_t val,
                          int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_LEUW | MO_UNALN, mmu_idx);
    cpu_stw_shadow(env, addr, val, oi, ra);
}

void cpu_stl_le_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr, uint32_t val,
                          int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_LEUL | MO_UNALN, mmu_idx);
    cpu_stl_shadow(env, addr, val, oi, ra);
}

void cpu_stq_le_shadow_mmuidx_ra(CPUArchState *env, abi_ptr addr, uint64_t val,
                          int mmu_idx, uintptr_t ra)
{
    MemOpIdx oi = make_memop_idx(MO_LEUQ | MO_UNALN, mmu_idx);
    cpu_stq_shadow(env, addr, val, oi, ra);
}

/*--------------------------*/

uint32_t cpu_ldub_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return cpu_ldub_shadow_mmuidx_ra(env, addr, cpu_mmu_index(env, false), ra);
}

int cpu_ldsb_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return (int8_t)cpu_ldub_shadow_ra(env, addr, ra);
}

uint32_t cpu_lduw_be_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return cpu_lduw_be_shadow_mmuidx_ra(env, addr, cpu_mmu_index(env, false), ra);
}

int cpu_ldsw_be_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return (int16_t)cpu_lduw_be_shadow_ra(env, addr, ra);
}

uint32_t cpu_ldl_be_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return cpu_ldl_be_shadow_mmuidx_ra(env, addr, cpu_mmu_index(env, false), ra);
}

uint64_t cpu_ldq_be_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return cpu_ldq_be_shadow_mmuidx_ra(env, addr, cpu_mmu_index(env, false), ra);
}

uint32_t cpu_lduw_le_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return cpu_lduw_le_shadow_mmuidx_ra(env, addr, cpu_mmu_index(env, false), ra);
}

int cpu_ldsw_le_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return (int16_t)cpu_lduw_le_shadow_ra(env, addr, ra);
}

uint32_t cpu_ldl_le_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return cpu_ldl_le_shadow_mmuidx_ra(env, addr, cpu_mmu_index(env, false), ra);
}

uint64_t cpu_ldq_le_shadow_ra(CPUArchState *env, abi_ptr addr, uintptr_t ra)
{
    return cpu_ldq_le_shadow_mmuidx_ra(env, addr, cpu_mmu_index(env, false), ra);
}

void cpu_stb_shadow_ra(CPUArchState *env, abi_ptr addr,
                     uint32_t val, uintptr_t ra)
{
    cpu_stb_shadow_mmuidx_ra(env, addr, val, cpu_mmu_index(env, false), ra);
}

void cpu_stw_be_shadow_ra(CPUArchState *env, abi_ptr addr,
                        uint32_t val, uintptr_t ra)
{
    cpu_stw_be_shadow_mmuidx_ra(env, addr, val, cpu_mmu_index(env, false), ra);
}

void cpu_stl_be_shadow_ra(CPUArchState *env, abi_ptr addr,
                        uint32_t val, uintptr_t ra)
{
    cpu_stl_be_shadow_mmuidx_ra(env, addr, val, cpu_mmu_index(env, false), ra);
}

void cpu_stq_be_shadow_ra(CPUArchState *env, abi_ptr addr,
                        uint64_t val, uintptr_t ra)
{
    cpu_stq_be_shadow_mmuidx_ra(env, addr, val, cpu_mmu_index(env, false), ra);
}

void cpu_stw_le_shadow_ra(CPUArchState *env, abi_ptr addr,
                        uint32_t val, uintptr_t ra)
{
    cpu_stw_le_shadow_mmuidx_ra(env, addr, val, cpu_mmu_index(env, false), ra);
}

void cpu_stl_le_shadow_ra(CPUArchState *env, abi_ptr addr,
                        uint32_t val, uintptr_t ra)
{
    cpu_stl_le_shadow_mmuidx_ra(env, addr, val, cpu_mmu_index(env, false), ra);
}

void cpu_stq_le_shadow_ra(CPUArchState *env, abi_ptr addr,
                        uint64_t val, uintptr_t ra)
{
    cpu_stq_le_shadow_mmuidx_ra(env, addr, val, cpu_mmu_index(env, false), ra);
}

/*--------------------------*/

uint32_t cpu_ldub_taint(CPUArchState *env, abi_ptr addr)
{
    return cpu_ldub_shadow_ra(env, addr, 0);
}

int cpu_ldsb_taint(CPUArchState *env, abi_ptr addr)
{
    return (int8_t)cpu_ldub_taint(env, addr);
}

uint32_t cpu_lduw_be_taint(CPUArchState *env, abi_ptr addr)
{
    return cpu_lduw_be_shadow_ra(env, addr, 0);
}

int cpu_ldsw_be_taint(CPUArchState *env, abi_ptr addr)
{
    return (int16_t)cpu_lduw_be_taint(env, addr);
}

uint32_t cpu_ldl_be_taint(CPUArchState *env, abi_ptr addr)
{
    return cpu_ldl_be_shadow_ra(env, addr, 0);
}

uint64_t cpu_ldq_be_taint(CPUArchState *env, abi_ptr addr)
{
    return cpu_ldq_be_shadow_ra(env, addr, 0);
}

uint32_t cpu_lduw_le_taint(CPUArchState *env, abi_ptr addr)
{
    return cpu_lduw_le_shadow_ra(env, addr, 0);
}

int cpu_ldsw_le_taint(CPUArchState *env, abi_ptr addr)
{
    return (int16_t)cpu_lduw_le_taint(env, addr);
}

uint32_t cpu_ldl_le_taint(CPUArchState *env, abi_ptr addr)
{
    return cpu_ldl_le_shadow_ra(env, addr, 0);
}

uint64_t cpu_ldq_le_taint(CPUArchState *env, abi_ptr addr)
{
    return cpu_ldq_le_shadow_ra(env, addr, 0);
}

void cpu_stb_taint(CPUArchState *env, abi_ptr addr, uint32_t val)
{
    cpu_stb_shadow_ra(env, addr, val, 0);
}

void cpu_stw_be_taint(CPUArchState *env, abi_ptr addr, uint32_t val)
{
    cpu_stw_be_shadow_ra(env, addr, val, 0);
}

void cpu_stl_be_taint(CPUArchState *env, abi_ptr addr, uint32_t val)
{
    cpu_stl_be_shadow_ra(env, addr, val, 0);
}

void cpu_stq_be_taint(CPUArchState *env, abi_ptr addr, uint64_t val)
{
    cpu_stq_be_shadow_ra(env, addr, val, 0);
}

void cpu_stw_le_taint(CPUArchState *env, abi_ptr addr, uint32_t val)
{
    cpu_stw_le_shadow_ra(env, addr, val, 0);
}

void cpu_stl_le_taint(CPUArchState *env, abi_ptr addr, uint32_t val)
{
    cpu_stl_le_shadow_ra(env, addr, val, 0);
}

void cpu_stq_le_taint(CPUArchState *env, abi_ptr addr, uint64_t val)
{
    cpu_stq_le_shadow_ra(env, addr, val, 0);
}


#if 0
/* --------------------------- */


tcg_target_ulong helper_ldub_shadow(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_8);
    return do_ld1_shadow(env_cpu(env), addr, oi, retaddr, MMU_DATA_LOAD);
}

tcg_target_ulong helper_lduw_shadow(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_16);
    return do_ld2_shadow(env_cpu(env), addr, oi, retaddr, MMU_DATA_LOAD);
}

tcg_target_ulong helper_ldul_shadow(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_32);
    return do_ld4_shadow(env_cpu(env), addr, oi, retaddr, MMU_DATA_LOAD);
}

uint64_t helper_ldq_shadow(CPUArchState *env, uint64_t addr,
                        MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_64);
    return do_ld8_shadow(env_cpu(env), addr, oi, retaddr, MMU_DATA_LOAD);
}

/*
 * Provide signed versions of the load routines as well.  We can of course
 * avoid this for 64-bit data, or for 32-bit data on 32-bit host.
 */

tcg_target_ulong helper_ldsb_shadow(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr)
{
    return (int8_t)helper_ldub_shadow(env, addr, oi, retaddr);
}

tcg_target_ulong helper_ldsw_shadow(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr)
{
    return (int16_t)helper_lduw_shadow(env, addr, oi, retaddr);
}

tcg_target_ulong helper_ldsl_shadow(CPUArchState *env, uint64_t addr,
                                 MemOpIdx oi, uintptr_t retaddr)
{
    return (int32_t)helper_ldul_shadow(env, addr, oi, retaddr);
}

Int128 helper_ld16_shadow(CPUArchState *env, uint64_t addr,
                       MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_128);
    return do_ld16_shadow(env_cpu(env), addr, oi, retaddr);
}

Int128 helper_ld_i128(CPUArchState *env, uint64_t addr, uint32_t oi)
{
    return helper_ld16_shadow(env, addr, oi, GETPC());
}

/*
 * Store helpers for tcg-ldst.h
 */

void helper_stb_shadow(CPUArchState *env, uint64_t addr, uint32_t val,
                    MemOpIdx oi, uintptr_t ra)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_8);
    do_st1_shadow(env_cpu(env), addr, val, oi, ra);
}

void helper_stw_shadow(CPUArchState *env, uint64_t addr, uint32_t val,
                    MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_16);
    do_st2_shadow(env_cpu(env), addr, val, oi, retaddr);
}

void helper_stl_shadow(CPUArchState *env, uint64_t addr, uint32_t val,
                    MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_32);
    do_st4_shadow(env_cpu(env), addr, val, oi, retaddr);
}

void helper_stq_shadow(CPUArchState *env, uint64_t addr, uint64_t val,
                    MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_64);
    do_st8_shadow(env_cpu(env), addr, val, oi, retaddr);
}

void helper_st16_shadow(CPUArchState *env, uint64_t addr, Int128 val,
                     MemOpIdx oi, uintptr_t retaddr)
{
    tcg_debug_assert((get_memop(oi) & MO_SIZE) == MO_128);
    do_st16_shadow(env_cpu(env), addr, val, oi, retaddr);
}

void helper_st_i128(CPUArchState *env, uint64_t addr, Int128 val, MemOpIdx oi)
{
    helper_st16_shadow(env, addr, val, oi, GETPC());
}
#endif
