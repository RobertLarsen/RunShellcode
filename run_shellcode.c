#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int create_server(unsigned short port, int ip_version) {
    int server;
    int flags;
    int addr_size;
    union {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } addr;

    if (ip_version == 6) {
        server = socket(AF_INET6, SOCK_STREAM, 0);
        if (server < 0) {
            return -1;
        }

        flags = 1;
        if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags)) < 0) {
            close(server);
            return -1;
        }

        addr.ipv6.sin6_family = AF_INET6;
        addr.ipv6.sin6_port = htons(port);
        addr.ipv6.sin6_addr = in6addr_any;
        addr_size = sizeof(struct sockaddr_in6);
    } else {
        server = socket(AF_INET, SOCK_STREAM, 0);
        if (server < 0) {
            return -1;
        }

        flags = 1;
        if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags)) < 0) {
            close(server);
            return -1;
        }

        addr.ipv4.sin_family = AF_INET;
        addr.ipv4.sin_port = htons(port);
        addr.ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
        addr_size = sizeof(struct sockaddr_in);
    }

    if (bind(server, (struct sockaddr*)&addr, addr_size) < 0) {
        close(server);
        return -1;
    }

    if (listen(server, 10) < 0) {
        close(server);
        return -1;
    }

    return server;
}

void child_died(int sig) {
    wait(&sig);
}

int main(int argc, char ** argv) {
    pid_t pid;
    size_t len;
    struct stat st;
    int again, i, server, client, val, fd, r, ip_version = 4;
    struct timeval timeout = {1, 0};
    unsigned short port;
    int (*shellcode)();

    if (argc > 1) {
        if (stat(argv[1], &st) == 0) {
            /* We have a file */
            len = (st.st_size + 4096 - 1) & ~(4096-1);
            if ((fd = open(argv[1], O_RDWR)) >= 0) {
                if ((shellcode = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0)) != MAP_FAILED) {
                    shellcode();
                    munmap(shellcode, len);
                }
                close(fd);
            }
        } else if ((port = atoi(argv[1])) >= 1024) {
            if (argc > 2) {
                ip_version = atoi(argv[2]);
            }
            if (ip_version != 4 && ip_version != 6) {
                fprintf(stderr, "Bad IP version.\n");
                _exit(-1);
            }
            /* We have a port */
            signal(SIGCHLD, child_died);

            if ((server = create_server(port, ip_version)) >= 0) {
                while ((client = accept(server, NULL, NULL)) >= 0) {
#if defined(FORK_SERVER)
                    pid = fork();
                    if (pid) {
                        /* Parent */
                        close(client);
                    } else {
                        /* Child */
                        close(server);
                        again = 1;
#endif
                        while (again) {
                            /* Remap every time so that caches are sure to be flushed */
                            shellcode = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                            if ((val = read(client, shellcode, 4096)) > 0) {
                                val = shellcode();
                                write(client, &val, sizeof(val));
                            } else {
                                again = 0;
                            }

                            munmap(shellcode, 4096);
                        }
                        close(client);
#if defined(FORK_SERVER)
                    }
#endif
                }
            } else {
                fprintf(stderr, "Could not create server.\n");
            }
        } else {
            fprintf(stderr, "%s is not a readable file and not a usable port.\n", argv[1]);
            return 1;
        }
    } else {
        /* No arguments, read from stdin (for xinetd) */
    }
    return 0;
}
