// tcp_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 7777
#define BUFFER_SIZE 1024

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char command[BUFFER_SIZE];

    // Création du socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Erreur de création du socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Adresse IP du serveur
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Adresse invalide ou non supportée");
        exit(EXIT_FAILURE);
    }

    // Connexion au serveur
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur de connexion au serveur");
        exit(EXIT_FAILURE);
    }

    printf("Connecté au serveur sur le port %d. Tapez vos commandes :\n", PORT);

    while (1) {
        printf("> ");
        fgets(command, BUFFER_SIZE, stdin);

        // Enlever le saut de ligne
        command[strcspn(command, "\n")] = 0;

        // Envoi de la commande au serveur
        send(sock, command, strlen(command), 0);

        // Quitter si la commande est "exit"
        if (strcmp(command, "exit") == 0) {
            break;
        }

        // Lire la réponse du serveur
        int bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("%s\n", buffer);
        } else {
            printf("Connexion au serveur terminée.\n");
            break;
        }
    }

    close(sock);
    return 0;
}
