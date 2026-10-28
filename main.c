#define _GNU_SOURCE

#if defined(__aarch64__)
     #include <bits/elf_common.h>
#else
     #include <elf.h>
#endif
#include <linux/elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/ptrace.h>  // Defines PTRACE_GETREGSET, NT_PRSTATUS, etc.
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/uio.h>       // For struct iovec
#include <sys/user.h>
#include <link.h>
#include <dlfcn.h>// for dlopen constants

#include "getdlopen.h"

#define CMDLINE_PATH_LEN 256

#ifndef __NR_mmap
// common on aarch64
#define __NR_mmap 222
#endif

int get_pid_by_name(const char *name) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            const char *pid_str = entry->d_name;

            // Check if directory name is all digits
            int is_pid = 1;
            for (const char *p = pid_str; *p; p++) {
                if (!isdigit((unsigned char)*p)) {
                    is_pid = 0;
                    break;
                }
            }
            if (!is_pid) continue;

            char cmdline_path[256];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", pid_str);

            FILE *cmdline_file = fopen(cmdline_path, "r");
            if (cmdline_file) {
                char cmdline[4096];
                size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file);
                fclose(cmdline_file);

                if (len > 0) {
                    cmdline[len] = '\0'; // ensure null-terminated

                    if (strstr(cmdline, name) != NULL) {
                        closedir(proc_dir);
                        return atoi(pid_str);
                    }
                }
            }
        }
    }

    closedir(proc_dir);
    return -1;
}

int do_remote_mmap_syscall(pid_t pid, size_t length, uintptr_t *out_addr) {
    struct user_pt_regs regs, backup;
    struct iovec iov;
    int status;

    // read regs
    iov.iov_base = &regs;
    iov.iov_len  = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_GETREGSET");
        return -1;
    }
    memcpy(&backup, &regs, sizeof(regs));

    // ensure PC is 4-byte aligned
    if (regs.pc & 3) {
        fprintf(stderr, "Unaligned PC: 0x%llx\n", (unsigned long long)regs.pc);
        return -1;
    }

    // save original word at PC (8 bytes)
    int errno = 0;
    unsigned long orig_word = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.pc, NULL);
    if (orig_word == (unsigned long)-1 && errno) { perror("PTRACE_PEEKTEXT"); return -1; }

    // AArch64 svc #0 encoding: 0xd4000001 (4 bytes)
    uint32_t svc32 = 0xd4000001u;
    // build new word: replace low 4 bytes with svc32, keep high 4 bytes
    unsigned long new_word = (orig_word & 0xffffffff00000000UL) | (unsigned long)svc32;

    // write patched word
    if (ptrace(PTRACE_POKETEXT, pid, (void*)regs.pc, (void*)new_word) == -1) {
        perror("PTRACE_POKETEXT");
        // try restoring if partial: not much we can do
        return -1;
    }

    // set up syscall args in registers: x0..x5, x8 = syscall number
    regs.regs[0] = 0;                     // addr = NULL
    regs.regs[1] = (unsigned long)length; // length
    regs.regs[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.regs[4] = (unsigned long)-1;     // fd
    regs.regs[5] = 0;                     // offset
    regs.regs[8] = (unsigned long)__NR_mmap; // x8 = syscall number

    // write regs back
    iov.iov_base = &regs;
    iov.iov_len  = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_SETREGSET");
        // restore original instruction before returning
        ptrace(PTRACE_POKETEXT, pid, (void*)regs.pc, (void*)orig_word);
        return -1;
    }

    // single-step to execute svc instruction only
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        perror("PTRACE_SINGLESTEP");
        ptrace(PTRACE_POKETEXT, pid, (void*)regs.pc, (void*)orig_word);
        return -1;
    }

    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        ptrace(PTRACE_POKETEXT, pid, (void*)regs.pc, (void*)orig_word);
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Tracee not stopped after SINGLESTEP (status=%x)\n", status);
        ptrace(PTRACE_POKETEXT, pid, (void*)regs.pc, (void*)orig_word);
        return -1;
    }

    // read registers again; return value in x0
    iov.iov_base = &regs;
    iov.iov_len  = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_GETREGSET after step");
        ptrace(PTRACE_POKETEXT, pid, (void*)backup.pc, (void*)orig_word);
        return -1;
    }

    unsigned long ret = (unsigned long)regs.regs[0];

    // restore original instruction
    if (ptrace(PTRACE_POKETEXT, pid, (void*)backup.pc, (void*)orig_word) == -1) {
        perror("PTRACE_POKETEXT restore");
        // continue restoring regs below regardless
    }

    // restore original regs
    iov.iov_base = &backup;
    iov.iov_len  = sizeof(backup);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_SETREGSET restore");
    }

    // detach tracee (continue it)
    /*if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_DETACH");
    }*/

    *out_addr = (uintptr_t)ret;
    return 0;
}

int main(int argc, char *argv[]){

    if(argc<3){
        printf("Usage: soinjector <pid> <so_path>\n");
        return 1;
    }

    if(geteuid()!=0){
        printf("Please run as root!\n");
        return 1;
    }

    char* proc_name = argv[1];
    char* so_name = argv[2];

    if (access(so_name, F_OK) != 0) {
        printf("Provided .so file doesn't exist!\n");
        return 1;
    }

    char resolved_so_path[4096]; // large enough buffer

    if (realpath(so_name, resolved_so_path) != NULL) {
        printf("Absolute path of .so: %s\n", resolved_so_path);
    } else {
        perror("realpath");
        return 1;
    }

    printf("Searching for pid of process with name %s ...\n",proc_name);

    int target_pid = get_pid_by_name(proc_name);


    if(target_pid == -1){
        printf("Couldnt find pid of process!\n");
        return 1;
    }

    printf("=> Target pid: %d\n", target_pid);

    
    // get address of important functions in target 

    uintptr_t target_dlopen = find_remote_dlopen(target_pid);

    printf("=> Target dlopen addr: 0x%lx\n", target_dlopen);


    printf("Attaching to target process ...\n");

    ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);

    int status;
    if (waitpid(target_pid, &status, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    if (WIFSTOPPED(status)) {
        printf("Process %d stopped, attached successfully\n", target_pid);
    } else {
        fprintf(stderr, "Unexpected wait status\n");
        return 1;
    }

    struct user_pt_regs regs, backup;

    struct iovec iov;

    // read regs
    iov.iov_base = &regs;
    iov.iov_len  = sizeof(regs);                                       if (ptrace(PTRACE_GETREGSET, target_pid, (void*)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_GETREGSET");
        return -1;
    }                                                                  memcpy(&backup, &regs, sizeof(regs));



    printf("Calling mmap using syscall ...\n");

    uintptr_t memalloc_addr = 0;
    if (do_remote_mmap_syscall(target_pid, 0x1000, &memalloc_addr) == 0) {
        if ((long long)memalloc_addr == -1LL) {
            printf("mmap failed, returned -1\n");
        } else {
            printf("mmap returned: 0x%lx\n", (unsigned long)memalloc_addr);
        }
    } else {
        fprintf(stderr, "remote mmap syscall failed\n");
    }

    printf("Injecting dlopen return code (0xd4200000) ...\n");

    uint32_t brk_insn = 0xd43e0000; //0xd4200000; // brk #0
    ptrace(PTRACE_POKETEXT, target_pid, (void*)memalloc_addr, (void*)brk_insn);

    // After the instruction
    uintptr_t sopath_string_addr = memalloc_addr + 4;


    printf("Injecting so path string to target process ...\n");

    struct iovec local_iov = {
        .iov_base = resolved_so_path,
        .iov_len = strlen(resolved_so_path) + 1
    };

    struct iovec remote_iov = {
        .iov_base = (void *)sopath_string_addr,
        .iov_len = strlen(resolved_so_path) + 1
    };

    ssize_t nwritten = process_vm_writev(target_pid, &local_iov, 1, &remote_iov, 1, 0);

    if (nwritten == -1) {
        perror("process_vm_writev");
        return 1;
    }

    printf("Wrote %zd bytes to process %d\n", nwritten, target_pid);

    printf("Attempting to call dlopen inside remote process ...\n");

    // call dlopen
    // Set up for dlopen(remote_str_addr, RTLD_NOW)
    regs.pc = target_dlopen;          // Function entry point
    regs.regs[0] = sopath_string_addr;      // arg0: path to .so in target mem
    regs.regs[1] = RTLD_NOW;             // arg1: flags
    // Optional: ensure SP alignment (16-byte)
    regs.sp &= ~0xF;

    regs.regs[30] = memalloc_addr; // set lr to address with assembly code that triggers SIGTRAP

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    // Write back registers
    ptrace(PTRACE_SETREGSET, target_pid, (void*)NT_PRSTATUS, &iov);

    // Continue to execute dlopen
    ptrace(PTRACE_CONT, target_pid, NULL, NULL);


    // --- Wait for dlopen to return ---
    status = 0;
    waitpid(target_pid, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // dlopen has returned, handle is in x0
        ptrace(PTRACE_GETREGSET, target_pid, (void*)NT_PRSTATUS, &iov);
        void *dlopen_handle = (void *)regs.regs[0];
        printf("dlopen returned: %p\n", dlopen_handle);
    } else {
        printf("!!!!!!!: %i, %i \n", WIFSTOPPED(status), WSTOPSIG(status));
        ptrace(PTRACE_GETREGSET, target_pid, (void*)NT_PRSTATUS, &iov);
        printf("=== DEBUG ===\nPC: 0x%llx\n", regs.pc);

        siginfo_t si;
        ptrace(PTRACE_GETSIGINFO, target_pid, NULL, &si);

        printf("SIGSEGV at address: %p\n", si.si_addr);
    }

    // --- Restore original registers ---
    iov.iov_base = &backup;
    iov.iov_len  = sizeof(backup);
    ptrace(PTRACE_SETREGSET, target_pid, (void*)NT_PRSTATUS, &iov);



    printf("Injection done!\n");

    // detach
    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
        perror("PTRACE_DETACH");
    }
    

    /*ptrace(PTRACE_GETREGSET, target_pid, NULL, &regs);
    memcpy(&backup, &regs, sizeof(regs));

    printf("Target PC: 0x%llx\n",regs.pc);
    
    regs.regs[0] = 0;        // addr = NULL
    regs.regs[1] = 0x1000;   // length = 4096
                             // bytes
    regs.regs[2] = 0x7;      // prot = PROT_READ|PROT_WRITE|PROT_EXEC
    regs.regs[3] = 0x22;     // flags = MAP_PRIVATE|MAP_ANONYMOUS
    regs.regs[4] = -1;       // fd = -1
    regs.regs[5] = 0;        // offset = 0
    regs.pc      = target_mmap; // PC = target libc mmap address
    
    ptrace(PTRACE_SETREGSET, target_pid, NULL, &regs);

    waitpid(target_pid, NULL, 0);

    ptrace(PTRACE_GETREGSET, target_pid, NULL, &regs);
    unsigned long long mmap_addr = regs.regs[0]; // return value from mmap
    printf("Allocated address: 0x%llx\n", mmap_addr);
*/

    

}

