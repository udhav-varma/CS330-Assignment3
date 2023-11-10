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
    return -EINVAL;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    struct vm_area * list = current->vm_area;
    if(list == NULL){
        struct vm_area * headnode = (struct vm_area *) os_alloc(sizeof(struct vm_area));
        headnode->access_flags = 0x0;
        headnode->vm_start = MMAP_AREA_START;
        headnode->vm_end = MMAP_AREA_START + 4096;
        headnode->vm_next = NULL;
        current->vm_area = headnode;
    }
    if(addr < MMAP_AREA_START || addr >= MMAP_AREA_END) return -EINVAL;
    int allotAddr = -EINVAL;
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
        struct vm_area * ptr = current->vm_area, * pptr = ptr;
        while(ptr != NULL){
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
    struct vm_area * pptr = current->vm_area, *ptr = pptr->vm_next;
    while(ptr != NULL){
        struct vm_area * hptr = ptr->vm_next;
        struct vm_area * prev = ptr;
        while(hptr != NULL && prev->access_flags == hptr->access_flags && prev->vm_end == hptr->vm_start){
            struct vm_area * hold = hptr;
            prev = hptr;
            hptr = hptr->vm_next;
            os_free(hold, sizeof(struct vm_area));
        }
        ptr->vm_end = prev->vm_end;
        ptr->vm_next = hptr;
        pptr = ptr;
        ptr = ptr->vm_next;        
    }
}
    return allotAddr;
}

/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    return -EINVAL;
}



/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
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
