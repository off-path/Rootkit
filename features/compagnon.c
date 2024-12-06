#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

void execute_file(const char *file_path) {
    struct stat file_stat;

    // Vérifier si le fichier existe et est exécutable
    if (stat(file_path, &file_stat) == -1 || !(file_stat.st_mode & S_IXUSR)) {
        exit(EXIT_FAILURE);
    }

    // Préparer les arguments (ici aucun paramètre supplémentaire)
    char *args[] = {(char *)file_path, NULL};

    // Exécuter le fichier
    execv(file_path, args);

    // Si execv échoue
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return EXIT_FAILURE;
    }

    execute_file(argv[1]);

    return EXIT_SUCCESS; // Ne sera jamais atteint si execv réussit
}
