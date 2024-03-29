#include <stdio.h>
#include <malloc.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

static char *chroot_path = NULL;
static int do_fork = 0, uid = -1, gid = -1;
static unsigned int timeout = 0;
static enum { Undecided, IPv4, IPv6 } ip_version = Undecided;
static void (*shellcode)() = NULL;

static void child_died(int sig) {
    wait(&sig);
}

static int create_server(unsigned short port) {
    int server;
    int flags;
    int addr_size;
    union {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } addr;

    if (ip_version == IPv6) {
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

static void execute_shellcode() {
    if (chroot_path && chroot(chroot_path)) {
        exit(-1);
    }

    if (gid != -1 && setgid(gid)) {
        exit(-1);
    }

    if (uid != -1 && setuid(uid)) {
        exit(-1);
    }

    if (timeout > 0) {
        alarm(timeout);
    }

    shellcode();
    exit(0);
}

void help(char *path) {
    printf( "Usage: %s <arguments> ([file]|[tcp port])\n"
            "   Shellcode can be passed either as standard in, on a tcp port\n"
            "   or as a file.\n"
            "   If the last argument exists as a file, it will be read and\n"
            "   executed. If the last argument is a number, a tcp server will\n"
            "   listen on that port and read up to 4096 bytes in ONE read and\n"
            "   then execute that. If neither option is specified, shellcode\n"
            "   will be read from standard in and then executed\n"
            "   \n"
            "   Available options:\n"
            "   --ipv4              Use IPv4 for the tcp server.\n"
            "   --ipv6              Use IPv6 for the tcp server.\n"
            "   --fork              Fork the tcp server for each client.\n"
            "   --chroot <path>     Change root path before executing shellcode.\n"
            "                       This option requires root.\n"
            "   --uid <uid>         Change user id to this before executing shellcode.\n"
            "   --gid <gid>         Change group id to this before executing shellcode.\n"
            "   --timeout <seconds> Exit <seconds> after starting the shellcode.\n"
            "   --help              Show this help.\n", path);
}

void handle_alarm(int sig) {
    exit(0);
}

int main(int argc, char ** argv) {
    struct stat st;
    int server, client, fd, c, opt_idx = 0, port, capacity, bytes_read, total_read;
    pid_t pid;

    static struct option long_options[] = {
        { "ipv4",           no_argument, 0, '4' },
        { "ipv6",           no_argument, 0, '6' },
        { "fork",           no_argument, 0, 'f' },
        { "chroot",   required_argument, 0, 'c' },
        { "uid",      required_argument, 0, 'u' },
        { "gid",      required_argument, 0, 'g' },
        { "timeout",  required_argument, 0, 't' },
        { "help",           no_argument, 0, 'h' },
        {          0,                 0, 0,  0  }
    };

    while ((c = getopt_long(argc, argv, "46c:u:g:t:", long_options, &opt_idx)) != -1) {
        switch (c) {
            case '4':
            case '6':
                if (ip_version == Undecided || ((c == '4' && ip_version == IPv4) || (c == '6' && ip_version == IPv6))) {
                    ip_version = c == '4' ? IPv4 : IPv6;
                } else {
                    fprintf(stderr, "Cannot specify both IPv4 and IPv6\n");
                    exit(1);
                }
                break;
            case 'f':
                do_fork = 1;
                break;
            case 'c':
                chroot_path = optarg;
                if (stat(chroot_path, &st) < 0 || (st.st_mode & S_IFMT) != S_IFDIR) {
                    fprintf(stderr, "Either \"%s\" does not exist or it is not a directory.\n", chroot_path);
                    exit(1);
                }
                if (access(chroot_path, X_OK) != 0) {
                    fprintf(stderr, "Cannot access \"%s\"\n", chroot_path);
                    exit(1);
                }
                break;
            case 'u':
                uid = atoi(optarg);
                break;
            case 'g':
                gid = atoi(optarg);
                break;
            case 'h':
                help(argv[0]);
                exit(0);
                break;
            case 't':
                timeout = strtoul(optarg, NULL, 10);
                break;
            case '?':
                printf("Unknown: %s\n", optarg);
                break;
        }
    }

    signal(SIGCHLD, child_died);
    signal(SIGALRM, handle_alarm);

    if (optind == argc) {
        /* Read shellcode from stdin */
        total_read = 0;
        capacity = 4096;
        shellcode = malloc(capacity);
        while ((bytes_read = read(0, (void*)shellcode + total_read, capacity - total_read)) > 0) {
            total_read += bytes_read;
            capacity *= 2;
            shellcode = realloc(shellcode, capacity);
        }
        mprotect((void*)((unsigned long)shellcode & ~4095), total_read + ((unsigned long)shellcode & 4095), PROT_READ|PROT_WRITE|PROT_EXEC);
        execute_shellcode();
    } else if (stat(argv[optind], &st) == 0) {
        /* Read shellcode from a file */
        if ((fd = open(argv[optind], O_RDONLY)) < 0) {
            fprintf(stderr, "Could not open file\n");
            exit(-1);
        }
        shellcode = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
        execute_shellcode();
    } else if ((port = atoi(argv[optind])) > 0) {
        /* Read shellcode from TCP server */
        if ((server = create_server(port)) < 0) {
            fprintf(stderr, "Could not create server\n");
            exit(-1);
        }

        do {
            while ((client = accept(server, NULL, NULL)) >= 0) {
                if (do_fork && (pid = fork())) {
                    close(client);
                } else {
                    close(server);
                    shellcode = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    if (read(client, shellcode, 4096) > 0) {
                        execute_shellcode();
                    }
                    exit(0);
                }
            }
        } while (errno == EINTR);

    } else {
        fprintf(stderr, "Cannot read shellcode from \"%s\"\n", argv[optind]);
        exit(1);
    }

    return 0;
}
