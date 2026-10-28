#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <errno.h>

static int parse_maps_line_range(const char *line, uintptr_t *start, uintptr_t *end, char *path, size_t pathlen) {
    // Format: addr-start-end perms offset dev inode pathname
    // We'll parse start-end and path if present.
    unsigned long s=0, e=0;
    int ret = sscanf(line, "%lx-%lx %*s %*s %*s %*s %s", &s, &e, path);
    if (ret >= 2) {
        *start = (uintptr_t)s;
        *end = (uintptr_t)e;
        if (ret == 3) return 1;
        path[0] = '\0';
        return 1;
    }
    return 0;
}

static uintptr_t find_local_mapping_containing(void *addr, char *out_path, size_t pathlen, uintptr_t *mapping_start) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[1024];
    uintptr_t as = 0, ae = 0;
    while (fgets(line, sizeof(line), fp)) {
        char pathbuf[512] = {0};
        if (!parse_maps_line_range(line, &as, &ae, pathbuf, sizeof(pathbuf))) continue;
        if ((uintptr_t)addr >= as && (uintptr_t)addr < ae) {
            if (out_path) {
                strncpy(out_path, pathbuf, pathlen-1);
                out_path[pathlen-1] = '\0';
            }
            if (mapping_start) *mapping_start = as;
            fclose(fp);
            return as;
        }
    }
    fclose(fp);
    return 0;
}

static uintptr_t find_remote_base_by_path(pid_t pid, const char *local_path) {
    if (!local_path || local_path[0] == '\0') return 0;
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        // only consider executable mapping (code segment)
        if (!strstr(line, "r-xp")) continue;
        if (strstr(line, local_path)) {
            uintptr_t start = 0, end = 0;
            char tmp[512] = {0};
            if (parse_maps_line_range(line, &start, &end, tmp, sizeof(tmp))) {
                fclose(fp);
                return start;
            }
        }
    }
    fclose(fp);
    return 0;
}

static uintptr_t find_remote_base_by_hint(pid_t pid) {
    // fallback: look for common linker strings or libdl/libc
    const char *hints[] = {"linker", "ld-", "linker64", "libdl.so", "libc.so"};
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "r-xp")) continue;
        for (size_t i = 0; i < sizeof(hints)/sizeof(hints[0]); ++i) {
            if (strstr(line, hints[i])) {
                uintptr_t start=0, end=0;
                char tmp[512] = {0};
                if (parse_maps_line_range(line, &start, &end, tmp, sizeof(tmp))) {
                    fclose(fp);
                    return start;
                }
            }
        }
    }
    fclose(fp);
    return 0;
}

uintptr_t find_remote_dlopen(pid_t pid) {
    // 1) find local dlopen address
    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen) {
        fprintf(stderr, "dlsym(RTLD_DEFAULT, \"dlopen\") failed: %s\n", dlerror());
        return 0;
    }

    // 2) find the local mapping that contains local_dlopen, and get its path and local base
    char local_path[512] = {0};
    uintptr_t local_base = 0;
    if (!find_local_mapping_containing(local_dlopen, local_path, sizeof(local_path), &local_base)) {
        // If we couldn't find the mapping containing dlopen, try to at least print debug.
        fprintf(stderr, "Could not find local mapping containing dlopen.\n");
        return 0;
    }

    if (local_path[0] == '\0') {
        // Sometimes dlsym resolves to an in-memory mapping with no path (unlikely for linker), fallback
        fprintf(stderr, "Local mapping for dlopen has no path. local_base=0x%lx\n", (unsigned long)local_base);
    } else {
        // Debug print
        //fprintf(stderr, "Local dlopen @ %p, local_base=0x%lx, path=%s\n", local_dlopen, (unsigned long)local_base, local_path);
    }

    // 3) look up the same path in the remote process maps
    uintptr_t remote_base = find_remote_base_by_path(pid, local_path);
    if (remote_base) {
        uintptr_t offset = (uintptr_t)local_dlopen - local_base;
        return remote_base + offset;
    }

    // 4) fallback: try hints (linker, linker64, libdl, libc)
    remote_base = find_remote_base_by_hint(pid);
    if (remote_base) {
        // best-effort: assume the symbol is at same offset relative to this base
        uintptr_t offset = (uintptr_t)local_dlopen - local_base;
        fprintf(stderr, "Warning: exact pathname not found remotely; using heuristic mapping at 0x%lx\n", (unsigned long)remote_base);
        return remote_base + offset;
    }

    // 5) final fallback: print remote maps for debugging
    {
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *fp = fopen(maps_path, "r");
        if (fp) {
            fprintf(stderr, "---- remote /proc/%d/maps ----\n", pid);
            char line[1024];
            while (fgets(line, sizeof(line), fp)) fputs(line, stderr);
            fprintf(stderr, "---- end remote maps ----\n");
            fclose(fp);
        } else {
            fprintf(stderr, "Could not open /proc/%d/maps for debugging: %s\n", pid, strerror(errno));
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    uintptr_t addr = find_remote_dlopen(pid);
    if (!addr) {
        fprintf(stderr, "Failed to resolve remote dlopen for pid %d\n", (int)pid);
        return 2;
    }
    printf("=> Target dlopen addr: 0x%lx\n", (unsigned long)addr);
    return 0;
}
