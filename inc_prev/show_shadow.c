#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define KEY_ESC 27
#define SFP "/etc/shadow"
#define PFP "/proc/inc_prev"

void send_pid(pid_t pid) {
    int fd = 0, bts = 0;

    fd = open(PFP, O_WRONLY);
    if (fd == -1) {
        perror("open(proc file)");
        exit(EXIT_FAILURE);
    }
    
    bts = write(fd, (char *)&pid, sizeof(pid_t));
    if (bts == -1) {
        perror("write");
        exit(EXIT_FAILURE);
    }
    else
        printf("send pid: %d", pid);
}

void sig_hndl(int sig_num) {
    int fd = 0;

    switch (sig_num) {
        /* Ctrl + C */
        case SIGINT:
            printf(": received signal SIGINT\nexit\n");
            exit(EXIT_SUCCESS);

        /* Ctrl + Z */
        case SIGTSTP: 
            printf(": received signal SIGTSTP\ntrying to open a file\n");
            fd = open(SFP, O_RDONLY); 

            if (fd != -1)
                printf("file successfully opened\n");
            else
                perror("unable to open file");

            close(fd);
            break;
    }

    printf("\n");
}

void init_signal(struct sigaction *sig_act) {
    int rtn = 0;

    memset(sig_act, 0, sizeof(struct sigaction));

    sig_act->sa_handler = sig_hndl;
    sigemptyset(&sig_act->sa_mask);
    sig_act->sa_flags = 0;

    rtn = sigaction(SIGINT, sig_act, NULL);
    if (rtn == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    rtn = sigaction(SIGTSTP, sig_act, NULL);
    if (rtn == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int main() {
    struct sigaction sig_act;
    pid_t pid = 0;

    pid = getpid();

    init_signal(&sig_act);
    send_pid(pid);

    do {
        sleep(1);
    } while(1);

    exit(EXIT_SUCCESS);
}
