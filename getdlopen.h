#ifndef GET_DLOPEN_H
#define GET_DLOPEN_H

#include <stdint.h>
#include <sys/types.h>  // for pid_t

#ifdef __cplusplus
extern "C" {
#endif

uintptr_t find_remote_dlopen(pid_t pid);

#ifdef __cplusplus
}
#endif

#endif // GET_DLOPEN_H

