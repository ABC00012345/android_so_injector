#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

__attribute__((constructor))
void write_time_to_file() {
    const char *path = "/data/data/com.PoxelStudios.DudeTheftAuto/files/TEST";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
        // Can't open file, just silently fail or print to stderr if you want
        return;
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) {
        close(fd);
        return;
    }

    char buf[64];
    int len = snprintf(buf, sizeof(buf), "Current UNIX time: %ld\n", (long)now);
    if (len > 0) {
        write(fd, buf, len);
    }

    close(fd);
}

