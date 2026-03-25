#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEVICE "/dev/ctf"

/* ioctl commands — must match your driver */
#define CTF_IOC_MAGIC   0xC7
#define CTF_SET_INPUT   _IOW(CTF_IOC_MAGIC, 0x01, char[64])
#define CTF_CHECK_INPUT _IO(CTF_IOC_MAGIC, 0x02)
#define CTF_GET_STATUS  _IOR(CTF_IOC_MAGIC, 0x03, char[16])

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    int fd = open(DEVICE, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* Send input to driver */
    char buf[64] = {0};
    strncpy(buf, argv[1], sizeof(buf) - 1);

    if (ioctl(fd, CTF_SET_INPUT, buf) < 0) {
        perror("ioctl SET_INPUT");
        close(fd);
        return 1;
    }

    /* Check input */
    if (ioctl(fd, CTF_CHECK_INPUT) < 0) {
        perror("ioctl CHECK_INPUT");
        close(fd);
        return 1;
    }

    /* Get status */
    char status[16] = {0};
    if (ioctl(fd, CTF_GET_STATUS, status) < 0) {
        perror("ioctl GET_STATUS");
        close(fd);
        return 1;
    }

    printf("Driver response: %s\n", status);

    close(fd);
    return 0;
}
