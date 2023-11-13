#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */

int present_page(u64 page_entry)
{
    return (page_entry&1);
}

/**
 * Dellocates page at `addr`
*/
void deallocate_page(struct exec_context * current, long addr)
{
    long pfn = current->pgd;
    long * table, offset;
    for(int c = 0; c < 4; c++){
        table = osmap(pfn);
        offset = ((addr >> (39 - 9*c)) & ((1ull << 9) - 1));
        // if(!present_page(table[offset])) return;
        pfn = (table[offset] >> 12);
    }

    if(present_page(table[offset])){
        if(get_pfn_refcount(pfn) == 1){
            put_pfn(pfn);
            os_pfn_free(USER_REG, pfn);
            table[offset] = 0;
        }
        else{
            put_pfn(pfn);
            table[offset] = 0;
        }
    }
    asm volatile("invlpg (%0)" :: "r" (addr) : "memory");
}

/**
 * Copies memory
*/
int memcopy(u64 begin, u64 pgd1, u64 pgd2)
{
    long * tab1 = osmap(pgd1), * tab2 = osmap(pgd2);
    for(int i = 0; i < 4; i++){
        long offset = ((begin >> (39 - 9*i)) & ((1ull << 9) - 1));
        if(!(tab1[offset]&1)){
            tab2[offset] = 0;
            break;
        }
        else if(i < 3){
            if(!(tab2[offset]&1)){
                long page = os_pfn_alloc(OS_PT_REG);
                if(page == 0) return -1;
                tab2[offset] = (page << 12) + (tab1[offset]&((1ull << 12) - 1));
            }
            tab1 = osmap(tab1[offset] >> 12);
            tab2 = osmap(tab2[offset] >> 12);
        }
        else{
            if(tab1[offset]&(1ull << 3)) tab1[offset] ^= (1ull << 3);
            tab2[offset] = tab1[offset];
            get_pfn(tab2[offset] >> 12);
            asm volatile("invlpg (%0)" :: "r" (begin): "memory");
        }
    }
    return 0;
}


/**
 * Copies range of addresses
*/
int memcopy_range(u64 begin, u64 end, u64 pgd1, u64 pgd2)
{
    // printk("here4\n");
    begin = (begin >> 12) << 12;
    for(long addr = begin; addr < end; addr += 4096){
        if(memcopy(addr, pgd1, pgd2) == -1) return -1;
    }
    return 0;
}

/**
 * Changes permission of page
*/
void change_access(struct exec_context * current, u64 addr, int prot)
{
    long pfn = current->pgd;
    long * table, offset;
    for(int c = 0; c < 4; c++){
        table = osmap(pfn);
        offset = ((addr >> (39 - 9*c)) & ((1ull << 9) - 1));
        if(!present_page(table[offset])) return;
        pfn = (table[offset] >> 12);
    }
    if(get_pfn_refcount(pfn) == 1){
        if(prot&O_WRITE){
            table[offset] |= (1ull << 3);
        }
        else{
            if(table[offset]&(1ull << 3)) table[offset] ^= (1ull << 3);
        }
    }
    else{
        if(!(prot & O_WRITE)){
            if(table[offset]&(1ull << 3)) table[offset] ^= (1ull << 3);
        }
    }
    asm volatile("invlpg (%0)" :: "r" (addr) : "memory");
}


void change_range_access(u64 start, u64 end, int prot, struct exec_context * curr)
{
    while(start < end){
        change_access(curr, start, prot);
        start += 4096;
    }
}

void deallocate_range(u64 start, u64 end, struct exec_context * curr)
{
    // printk("here %x %x\n", start, end);
    while(start < end){
        deallocate_page(curr, start);
        start += 4096;
    }
}

/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if(length < 0) return -EINVAL;
    length = (4096)*((length + 4095)/4096);
    struct vm_area * ptr = current->vm_area->vm_next, * pptr = current->vm_area;
    u64 end = addr + length;
    while(ptr != NULL && end > addr){
        if(addr < ptr->vm_start) addr = ptr->vm_start;
        if(addr < ptr->vm_end){
            if(addr == ptr->vm_start){
                if(end >= ptr->vm_end){
                    ptr->access_flags = prot;
                    change_range_access(addr, ptr->vm_end, prot, current);
                    addr = ptr->vm_end;
                }
                else{
                    struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    if(newnode == NULL) return -1;
                    newnode->access_flags = ptr->access_flags;
                    newnode->vm_end = ptr->vm_end;
                    newnode->vm_start = end;
                    newnode->vm_next = ptr->vm_next;
                    ptr->vm_next = newnode;
                    ptr->vm_end = end;
                    ptr->access_flags = prot;
                    change_range_access(addr, end, prot, current);
                    addr = end;
                }
            }
            else{
                if(end >= ptr->vm_end){
                    struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    if(newnode == NULL) return -1;
                    newnode->vm_start = addr;
                    newnode->vm_end = ptr->vm_end;
                    newnode->vm_next = ptr->vm_next;
                    newnode->access_flags = prot;
                    ptr->vm_end = addr;
                    ptr->vm_next = newnode;
                    change_range_access(addr, ptr->vm_end, prot, current);
                    addr = ptr->vm_end;
                }
                else{
                    struct vm_area * bwnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    struct vm_area * rnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    if(bwnode == NULL || rnode == NULL) return -1;
                    bwnode->access_flags = prot;
                    bwnode->vm_end = end;
                    bwnode->vm_start = addr;
                    bwnode->vm_next = rnode;
                    rnode->access_flags = ptr->access_flags;
                    rnode->vm_end = ptr->vm_end;
                    rnode->vm_next = ptr->vm_next;
                    rnode->vm_start = end;
                    ptr->vm_end = addr;
                    ptr->vm_next = bwnode;
                    change_range_access(addr, end, prot, current);
                    addr = end;
                }
            }
        }
        pptr = ptr;
        ptr = ptr->vm_next;
    }
mergenodes:
{
    struct vm_area * pptr = current->vm_area, *ptr = pptr->vm_next;
    while(ptr != NULL){
        struct vm_area * hptr = ptr->vm_next;
        struct vm_area * prev = ptr;
        while(hptr != NULL && prev->access_flags == hptr->access_flags && prev->vm_end == hptr->vm_start){
            prev = hptr;
            hptr = hptr->vm_next;
        }
        ptr->vm_end = prev->vm_end;
        struct vm_area * dptr = ptr->vm_next;
        while(dptr != hptr){
            struct vm_area * hold = dptr;
            dptr = dptr->vm_next;
            os_free(hold, sizeof(struct vm_area));
        }
        ptr->vm_next = hptr;
        pptr = ptr;
        ptr = ptr->vm_next;
    }
    int cnt = 0;
    ptr = current->vm_area;
    while(ptr != NULL){
        cnt++;
        ptr = ptr->vm_next;
    }
    stats->num_vm_area = cnt;
}
    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    struct vm_area * list = current->vm_area;
    if(list == NULL){
        // printk("Enter null\n");
        struct vm_area * headnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
        if(headnode == NULL) return -1;
        headnode->access_flags = 0x0;
        headnode->vm_start = MMAP_AREA_START;
        headnode->vm_end = MMAP_AREA_START + 4096;
        headnode->vm_next = NULL;
        current->vm_area = headnode;
        // printk("Headnode - %x %x\n", current->vm_area->vm_start, current->vm_area->vm_end);
        stats->num_vm_area = 1;
    }
    length = (4096)*((length + 4095)/4096);
    // printk("%d %d\n", addr, length);
    long allotAddr = -EINVAL;
    // printk("Enter main\n");
    if(flags == MAP_FIXED){
        if(addr == 0) return -EINVAL;
        if(!(addr >= MMAP_AREA_START && addr + length <= MMAP_AREA_END)) return -EINVAL;

        struct vm_area * ptr = current->vm_area, * pptr = ptr;
        while(ptr != NULL && ptr->vm_end <= addr){
            pptr = ptr;
            ptr = ptr->vm_next;
        }
        if(pptr->vm_end <= addr){
            if(ptr == NULL || ptr->vm_start >= addr + length){
                struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                if(newnode == NULL) return -1;
                newnode->vm_start = addr;
                newnode->vm_end = addr + length;
                newnode->access_flags = prot;
                newnode->vm_next = ptr;
                pptr->vm_next = newnode;
                allotAddr = addr;
                goto mergenodes;
            }
            else return -EINVAL;
        }
        else return -EINVAL;
    }
    else{
        if(addr != 0 && addr >= MMAP_AREA_START && addr + length <= MMAP_AREA_END){
            struct vm_area * ptr = current->vm_area, * pptr = ptr;
            while(ptr != NULL && ptr->vm_end <= addr){
                pptr = ptr;
                ptr = ptr->vm_next;
            }
            if(pptr->vm_end <= addr){
                if(ptr == NULL || ptr->vm_start >= addr + length){
                    struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    if(newnode == NULL) return -1;
                    newnode->vm_start = addr;
                    newnode->vm_end = addr + length;
                    newnode->access_flags = prot;
                    newnode->vm_next = ptr;
                    pptr->vm_next = newnode;
                    allotAddr = addr;
                    goto mergenodes;
                }
            }
        }
        // printk("In general allocation\n");
        struct vm_area * ptr = current->vm_area, * pptr = ptr;
        // printk("%x %x\n", ptr->vm_start, ptr->vm_end);
        while(ptr != NULL){
            // printk("enter\n");
            pptr = ptr;
            ptr = ptr->vm_next;
            if(ptr != NULL){
                if(ptr->vm_start >= pptr->vm_end + length){
                    struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    if(newnode == NULL) return -1;
                    newnode->vm_start = pptr->vm_end;
                    newnode->vm_end = pptr->vm_end + length;
                    newnode->access_flags = prot;
                    newnode->vm_next = ptr;
                    pptr->vm_next = newnode;
                    allotAddr = newnode->vm_start;
                    goto mergenodes;
                }
            }
            else{
                if(MMAP_AREA_END >= pptr->vm_end + length){
                    // printk("Allot\n");
                    struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    if(newnode == NULL) return -1;
                    newnode->vm_start = pptr->vm_end;
                    newnode->vm_end = pptr->vm_end + length;
                    newnode->access_flags = prot;
                    newnode->vm_next = ptr;
                    pptr->vm_next = newnode;
                    allotAddr = newnode->vm_start;
                    goto mergenodes;
                }
            }
        }
        return -EINVAL;
    }

mergenodes:
{
    // printk("In merge area %x\n", allotAddr);
    struct vm_area * pptr = current->vm_area, *ptr = pptr->vm_next;
    while(ptr != NULL){
        struct vm_area * hptr = ptr->vm_next;
        struct vm_area * prev = ptr;
        while(hptr != NULL && prev->access_flags == hptr->access_flags && prev->vm_end == hptr->vm_start){
            prev = hptr;
            hptr = hptr->vm_next;
        }
        ptr->vm_end = prev->vm_end;
        struct vm_area * dptr = ptr->vm_next;
        while(dptr != hptr){
            struct vm_area * hold = dptr;
            dptr = dptr->vm_next;
            os_free(hold, sizeof(struct vm_area));
        }
        ptr->vm_next = hptr;
        pptr = ptr;
        ptr = ptr->vm_next;
    }
    int cnt = 0;
    ptr = current->vm_area;
    while(ptr != NULL){
        cnt++;
        ptr = ptr->vm_next;
    }
    stats->num_vm_area = cnt;
}
    return allotAddr;
}

/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if(length < 0) return -EINVAL;
    length = (4096)*((length + 4095)/(4096));
    if(addr >= MMAP_AREA_END || addr < MMAP_AREA_START) return -EINVAL;
    struct vm_area * ptr = current->vm_area->vm_next, *pptr = current->vm_area;
    u64 end = addr + length;
    while(ptr != NULL && end > addr){
        if(addr < ptr->vm_start) addr = ptr->vm_start;
        if(addr < ptr->vm_end){
            if(addr == ptr->vm_start){
                if(end >= ptr->vm_end){
                    deallocate_range(addr, ptr->vm_end, current);
                    addr = ptr->vm_end;
                    pptr->vm_next = ptr->vm_next;
                    struct vm_area * hold = ptr;
                    ptr = ptr->vm_next;
                    os_free(hold, sizeof(struct vm_area));
                    continue;
                }
                else{
                    deallocate_range(addr, end, current);
                    ptr->vm_start = end;
                    addr = end;
                }
            }
            else{
                if(end >= ptr->vm_end){
                    u64 hold = ptr->vm_end;
                    ptr->vm_end = addr;
                    deallocate_range(addr, hold, current);
                    addr = hold;
                }
                else{
                    u64 hold = ptr->vm_end;
                    ptr->vm_end = addr;
                    deallocate_range(addr, end, current);
                    addr = end;
                    struct vm_area * endnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    if(endnode == NULL) return -1;
                    endnode->vm_start = end;
                    endnode->vm_end = hold;
                    endnode->access_flags = ptr->access_flags;
                    endnode->vm_next = ptr->vm_next;
                    ptr->vm_next = endnode;
                }
            }
        }

        pptr = ptr;
        ptr = ptr->vm_next;
    }
    int cnt = 0;
    ptr = current->vm_area;
    while(ptr != NULL){
        cnt++;
        ptr = ptr->vm_next;
    }
    stats->num_vm_area = cnt;
    return 0;
}



/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    struct vm_area * ptr = current->vm_area;
    if(ptr == NULL){
        struct vm_area * headnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
        if(headnode == NULL) return -1;
        headnode->access_flags = 0x0;
        headnode->vm_start = MMAP_AREA_START;
        headnode->vm_end = MMAP_AREA_START + 4096;
        headnode->vm_next = NULL;
        current->vm_area = headnode;
        stats->num_vm_area = 1;
    }
    while(ptr != NULL && ptr->vm_end <= addr){
        ptr = ptr->vm_next;
    }
    // printk("here2\n");
    if(ptr == NULL || ptr->vm_start > addr){
        return -1; // No matching vma
    }
    if(error_code == 0x6 && ((ptr->access_flags & O_WRITE) == 0)){
        return -1; // Write on area with no write access
    }
    if(error_code == 0x7){
        if((ptr->access_flags & O_WRITE) == 0) return -1;
        handle_cow_fault(current, addr, ptr->access_flags);
        // printk("here\n");
        return 1;
    }
    const long pru_flags = ((1ull << 4) | (1ull << 3) | 1ull);
    long * pgd = osmap(current->pgd);
    long pgd_off = ((addr & ((1ull << 48) - (1ull << 39))) >> 39);
    if(!present_page(pgd[pgd_off])){
        long pfnum = os_pfn_alloc(OS_PT_REG);
        pgd[pgd_off] = ((pfnum << 12) | pru_flags);
    }   
    long * pud = osmap(pgd[pgd_off] >> 12);
    long pud_off = ((addr & ((1ull << 39) - (1ull << 30))) >> 30);
    if(!present_page(pud[pud_off])){
        long pfnum = os_pfn_alloc(OS_PT_REG);
        pud[pud_off] = ((pfnum << 12) | pru_flags);
    }
    long *pmd = osmap(pud[pud_off] >> 12);
    long pmd_off = ((addr & ((1ull << 30) - (1ull << 21))) >> 21);
    if(!present_page(pmd[pmd_off])){
        long pfnum = os_pfn_alloc(OS_PT_REG);
        pmd[pmd_off] = ((pfnum << 12) | pru_flags);
    }
    long * pte = osmap(pmd[pmd_off] >> 12);
    long pte_off = ((addr & ((1ull << 21) - (1ull << 12))) >> 12);
    if(!present_page(pte[pte_off])){
        long pfnum = os_pfn_alloc(USER_REG);
        int rw_flag = 0;
        if((ptr->access_flags&O_WRITE) != 0) rw_flag = 1;
        pte[pte_off] = ((pfnum << 12) | (1ull << 4) | (rw_flag << 3) | 1);
    }

    return 1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */

long do_cfork(){
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
     /* Do not modify above lines
     * 
     * */   
     /*--------------------- Your code [start]---------------*/
     

     /*--------------------- Your code [end] ----------------*/
    // vm_area
    pid = new_ctx->pid;
    new_ctx->alarm_config_time = ctx->alarm_config_time;
    new_ctx->ctx_threads = ctx->ctx_threads;
    new_ctx->ppid = ctx->pid;
    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;
    new_ctx->regs = ctx->regs;
    new_ctx->state = ctx->state;
    new_ctx->type = ctx->type;
    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;
    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
    new_ctx->used_mem = ctx->used_mem;
    // new_ctx->os_stack_pfn = ctx->os_stack_pfn;
    // new_ctx->os_rsp = ctx->os_rsp;
    for(int i = 0; i < CNAME_MAX; i++){
        new_ctx->name[i] = ctx->name[i];
    }
    for(int i = 0; i < MAX_MM_SEGS; i++){
        new_ctx->mms[i] = ctx->mms[i];
    }
    for(int i = 0; i < MAX_SIGNALS; i++){
        new_ctx->sighandlers[i] = ctx->sighandlers[i];
    }
    for(int i = 0; i < MAX_OPEN_FILES; i++){
        new_ctx->files[i] = ctx->files[i];
    }

    new_ctx->pgd = os_pfn_alloc(OS_PT_REG);
    for(int i = 0; i <= 3; i++){
        u64 begin = ctx->mms[i].start, end = ctx->mms[i].end;
        if(i < 3) end = ctx->mms[i].next_free;
        // if(memcopy_range(begin, end, ctx->pgd, new_ctx->pgd) == -1) return -1;
        if(memcopy_range(begin, end, ctx->pgd, new_ctx->pgd) == -1) return -1;
    }

    if(ctx->vm_area != NULL){
        struct vm_area * headnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
        if(headnode == NULL) return -1;
        headnode->access_flags = 0x0;
        headnode->vm_start = MMAP_AREA_START;
        headnode->vm_end = MMAP_AREA_START + 4096;
        headnode->vm_next = NULL;
        new_ctx->vm_area = headnode;
        struct vm_area * ptr = ctx->vm_area->vm_next;
        struct vm_area * newpptr = new_ctx->vm_area;
        while(ptr != NULL){
            struct vm_area * addnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
            if(addnode == NULL) return -1;
            addnode->access_flags = ptr->access_flags;
            addnode->vm_start = ptr->vm_start;
            addnode->vm_end = ptr->vm_end;
            addnode->vm_next = NULL;
            newpptr->vm_next = addnode;
            addnode = newpptr;
            ptr = ptr->vm_next;
        }
    }
    if(ctx->vm_area){
        struct vm_area * ptr = ctx->vm_area->vm_next;
        while(ptr != NULL){
            // memcopy_range(ptr->vm_start, ptr->vm_end, ctx->pgd, new_ctx->pgd);
            memcopy_range(ptr->vm_start, ptr->vm_end, ctx->pgd, new_ctx->pgd);
            ptr = ptr->vm_next;
        }
    }
    // printk("here5 %d\n", pid);
     /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}


/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    u64 pfn = current->pgd;
    long * tab, offset;
    for(int i = 0; i < 4; i++){
        tab = osmap(pfn);
        offset = (vaddr >> (39 - 9*i))&((1ull << 9) - 1);
        pfn = (tab[offset] >> 12);
    }
    // printk("here3\n");
    int rc = get_pfn_refcount(pfn);
    if(rc > 1){
        u64 pfn2 = os_pfn_alloc(USER_REG);
        if(pfn2 == 0) return -1;
        tab[offset] = (pfn2 << 12) + (tab[offset]&(4095));
        tab[offset] |= 8;
        put_pfn(pfn);

        long * ad1 = osmap(pfn), * ad2 = osmap(pfn2);
        for(int i = 0; i < 512; i++) ad2[i] = ad1[i];
    }
    else{
        if(!(tab[offset] & (1ull << 3))) tab[offset] ^= (1ull << 3);
    }
    asm volatile("invlpg (%0)" :: "r" (vaddr) : "memory");
    return 1;
}
