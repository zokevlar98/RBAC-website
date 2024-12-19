#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>

#define PORT 8080
#define MAX_CLIENTS 10

int main(int argc, char const *argv[]) {
    int socket_fd, client_fd, max_fd, activity;
    struct sockaddr_in servdata, clientdata;
    fd_set readfds; // Set of file descriptors for select()
    int client_sockets[MAX_CLIENTS] = {0}; // Array to store client sockets
    socklen_t addrlen = sizeof(clientdata);

    // Create socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Initialize sockaddr_in structure
    servdata.sin_family = AF_INET;
    servdata.sin_port = htons(PORT);
    servdata.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Bind socket
    if (bind(socket_fd, (struct sockaddr *)&servdata, sizeof(servdata)) == -1) {
        perror("bind");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(socket_fd, MAX_CLIENTS) == -1) {
        perror("listen");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Main loop to handle connections
    while (1) {
        // Clear the socket set and add the server socket
        FD_ZERO(&readfds);
        FD_SET(socket_fd, &readfds);
        max_fd = socket_fd;

        // Add client sockets to the set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] > 0) {
                FD_SET(client_sockets[i], &readfds);
            }
            if (client_sockets[i] > max_fd) {
                max_fd = client_sockets[i];
            }
        }

        // Wait for activity on one of the sockets
        activity = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select");
            break;
        }

        // Check if the server socket has activity (new connection)
        if (FD_ISSET(socket_fd, &readfds)) {
            client_fd = accept(socket_fd, (struct sockaddr *)&clientdata, &addrlen);
            if (client_fd == -1) {
                perror("accept");
                continue;
            }

            printf("New connection from %s:%d\n",
                   inet_ntoa(clientdata.sin_addr),
                   ntohs(clientdata.sin_port));

            // Add the new client socket to the array
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = client_fd;
                    printf("Added client to slot %d\n", i);
                    break;
                }
            }
        }

        // Check activity on each client socket
        for (int i = 0; i < MAX_CLIENTS; i++) {
            client_fd = client_sockets[i];
            if (client_fd > 0 && FD_ISSET(client_fd, &readfds)) {
                char buffer[1024] = {0};
                int bytes_read = read(client_fd, buffer, sizeof(buffer));
                if (bytes_read == 0) {
                    // Connection closed
                    printf("Client disconnected, socket %d\n", client_fd);
                    close(client_fd);
                    client_sockets[i] = 0;
                } else {
                    // Echo message back to the client
                    printf("Received message: %s", buffer);
                    send(client_fd, buffer, bytes_read, 0);
                }
            }
        }
    }

    // Close the server socket
    close(socket_fd);

    return 0;
}
