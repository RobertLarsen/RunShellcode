#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

int main(int argc __attribute__((unused)), char ** argv __attribute__((unused))) {
    struct stat st;
    enum { Undecided, IPv4, IPv6 } ip_version = Undecided;
    char *chroot_path = NULL;
    int c, opt_idx = 0, do_fork = 0, port;

    static struct option long_options[] = {
        { "ipv4",           no_argument, 0, '4' },
        { "ipv6",           no_argument, 0, '6' },
        { "fork",           no_argument, 0, 'f' },
        { "chroot",   required_argument, 0, 'c' },
        { "userspec", required_argument, 0, 'u' },
        {          0,                 0, 0,  0  }
    };

    while ((c = getopt_long(argc, argv, "46c:u:", long_options, &opt_idx)) != -1) {
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
                break;
            case '?':
                printf("Unknown: %s\n", optarg);
                break;
        }
    }

    if (optind == argc) {
        printf("Get from stdin\n");
    } else if (stat(argv[optind], &st) == 0) {
        printf("Get from file\n");
    } else if ((port = atoi(argv[optind])) > 0) {
        printf("TCP\n");
    } else {
        fprintf(stderr, "Cannot read shellcode from \"%s\"\n", argv[optind]);
        exit(1);
    }

    return 0;
}
