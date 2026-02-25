/*
    Source code of ./exp/bin/socket_client.
    Will be put inside of the container to replace `/usr/bin/nsenter` while building the container.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080

int main()
{
    int sock;
    struct sockaddr_in serv_addr;
    char *message = "Hello from the container!";

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Connect
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }

    send(sock, message, strlen(message), 0);

    // Close socket
    close(sock);

    return 0;
}