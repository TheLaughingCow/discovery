#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iwlib.h>
#include <sys/stat.h>
#define MAX_BORNES 100

typedef struct {
    char ssid[IW_ESSID_MAX_SIZE + 1];
    int dbm;
    unsigned char mac[6];
} BorneWiFi;

// Fonction de comparaison pour le tri
int compare(const void *a, const void *b) {
    return ((BorneWiFi *)b)->dbm - ((BorneWiFi *)a)->dbm;
}

// Fonction pour trouver le nom de l'interface réseau sans fil
void get_wifi_interface_name(char *interface_name) {
    FILE *fp = popen("ip link show up | grep 'BROADCAST,MULTICAST' | cut -d: -f2 | tr -d ' '", "r");
    if (fp == NULL) {
        strcpy(interface_name, "unknown");
        return;
    }

    char ifname[16];
    struct stat statbuf;
    while (fgets(ifname, sizeof(ifname), fp)) {
        ifname[strcspn(ifname, "\n")] = 0;

        char wireless_path[64];
        snprintf(wireless_path, sizeof(wireless_path), "/sys/class/net/%s/wireless", ifname);

        if (stat(wireless_path, &statbuf) == 0) {
            strcpy(interface_name, ifname);
            pclose(fp);
            return;
        }
    }

    strcpy(interface_name, "unknown");
    pclose(fp);
}

// Fonction pour obtenir le SSID actuel
void get_current_ssid(char *current_ssid) {
    FILE *fp = popen("iwgetid -r", "r");
    if (fp == NULL) {
        strcpy(current_ssid, "");
        return;
    }

    if (fgets(current_ssid, IW_ESSID_MAX_SIZE, fp) == NULL) {
        strcpy(current_ssid, "");
    } else {
        // Enlever le saut de ligne à la fin si présent
        current_ssid[strcspn(current_ssid, "\n")] = 0;
    }
    pclose(fp);
}

// Fonction pour scanner les WiFi
void scan_wifi(char *interface) {
    wireless_scan_head head;
    wireless_scan *result;
    iwrange range;
    int sock;
    BorneWiFi bornes[MAX_BORNES];
    int count = 0;
    char current_ssid[IW_ESSID_MAX_SIZE + 1] = {0};

    // Obtenir le SSID actuel
    get_current_ssid(current_ssid);

    // Ouvrir un socket vers le noyau Linux
    sock = iw_sockets_open();

    // Récupérer les informations sur la plage de fréquences
    if (iw_get_range_info(sock, interface, &range) < 0) {
        printf("Erreur lors de la récupération des informations sur la plage de fréquences pour l'interface %s.\n", interface);
        iw_sockets_close(sock);
        return;
    }

    // Lancer le scan
    if (iw_scan(sock, interface, range.we_version_compiled, &head) < 0) {
        printf("Erreur lors du scan sur l'interface %s.\n", interface);
        iw_sockets_close(sock);
        return;
    }

    // Parcourir les résultats
    result = head.result;
    while (result && count < MAX_BORNES) {
        strncpy(bornes[count].ssid, result->b.essid, IW_ESSID_MAX_SIZE);
        bornes[count].ssid[IW_ESSID_MAX_SIZE] = '\0';
        bornes[count].dbm = result->stats.qual.level - 256;
        memcpy(bornes[count].mac, result->ap_addr.sa_data, 6);

        // Si le SSID actuel est vide (pas connecté), ou si le SSID du résultat correspond au SSID actuel, l'ajouter à la liste
        if (strlen(current_ssid) == 0 || strcmp(bornes[count].ssid, current_ssid) == 0) {
            count++;
        }

        result = result->next;
    }

    // Trier les bornes par dBm
    qsort(bornes, count, sizeof(BorneWiFi), compare);

    // Afficher les bornes
    for (int i = 0; i < count && i < 8; i++) {
        // Définir un SSID par défaut pour les SSID vides
        char *display_ssid = strlen(bornes[i].ssid) > 0 ? bornes[i].ssid : "!! caché !!";

        // Réglez la couleur en fonction de la force du signal
        if (bornes[i].dbm >= -64) {
            printf("\033[32m");  // Vert
        } else if (bornes[i].dbm >= -74) {
            printf("\033[33m");  // Orange
        } else {
            printf("\033[31m");  // Rouge
        }

        // Première ligne : SSID
        printf("%-20s\n", display_ssid);

        // Deuxième ligne : Adresse MAC et dBm
        printf("%02X:%02X:%02X:%02X:%02X:%02X %20d dBm\n",
            bornes[i].mac[0], bornes[i].mac[1], bornes[i].mac[2],
            bornes[i].mac[3], bornes[i].mac[4], bornes[i].mac[5],
            bornes[i].dbm);

        printf("\033[0m");  // Réinitialiser la couleur
        printf("\n");
    }

    // Fermer le socket
    iw_sockets_close(sock);
}

int main() {
    char interface_wifi[16];

    // Récupérer le nom de l'interface sans fil
    get_wifi_interface_name(interface_wifi);
    if (strcmp(interface_wifi, "unknown") == 0) {
        printf("Aucune interface sans fil n'a été trouvée.\n");
        return 1; // Quitter si aucune interface n'est trouvée
    }

    // Scanner les réseaux Wi-Fi en boucle
    while (1) {
        printf("\033[H\033[J");  // Effacer l'écran du terminal
        scan_wifi(interface_wifi);
        sleep(2);  // Attendre 2 secondes avant de rafraîchir
    }

    return 0;
}
