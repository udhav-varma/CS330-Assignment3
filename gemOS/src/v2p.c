#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */


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
                    addr = ptr->vm_end;
                }
                else{
                    struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    newnode->access_flags = ptr->access_flags;
                    newnode->vm_end = ptr->vm_end;
                    newnode->vm_start = end;
                    newnode->vm_next = ptr->vm_next;
                    ptr->vm_next = newnode;
                    ptr->vm_end = end;
                    ptr->access_flags = prot;
                    addr = end;
                }
            }
            else{
                if(end >= ptr->vm_end){
                    struct vm_area * newnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    newnode->vm_start = addr;
                    newnode->vm_end = ptr->vm_end;
                    newnode->vm_next = ptr->vm_next;
                    newnode->access_flags = prot;
                    ptr->vm_end = addr;
                    ptr->vm_next = newnode;
                    addr = ptr->vm_end;
                }
                else{
                    struct vm_area * bwnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
                    struct vm_area * rnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
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
                    addr = ptr->vm_end;
                    pptr->vm_next = ptr->vm_next;
                    struct vm_area * hold = ptr;
                    ptr = ptr->vm_next;
                    os_free(hold, sizeof(struct vm_area));
                    continue;
                }
                else{
                    ptr->vm_start = end;
                    addr = end;
                }
            }
            else{
                if(end >= ptr->vm_end){
                    u64 hold = ptr->vm_end;
                    ptr->vm_end = addr;
                    addr = hold;
                }
                else{
                    u64 hold = ptr->vm_end;
                    ptr->vm_end = addr;
                    addr = end;
                    struct vm_area * endnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
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
    while(ptr != NULL && ptr->vm_end <= addr){
        ptr = ptr->vm_next;
    }
    if(ptr == NULL || ptr->vm_start > addr){
        return -1; // No matching vma
    }
    if(error_code == 0x6 && ((ptr->access_flags & O_WRITE) == 0)){
        return -1; // Write on area with no write access
    }
    
    return -1;
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
  return -1;
}
