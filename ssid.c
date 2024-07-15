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

int compare(const void *a, const void *b) {
    return ((BorneWiFi *)b)->dbm - ((BorneWiFi *)a)->dbm;
}

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

void get_current_ssid(char *current_ssid) {
    FILE *fp = popen("iwgetid -r", "r");
    if (fp == NULL) {
        strcpy(current_ssid, "");
        return;
    }

    if (fgets(current_ssid, IW_ESSID_MAX_SIZE, fp) == NULL) {
        strcpy(current_ssid, "");
    } else {
        current_ssid[strcspn(current_ssid, "\n")] = 0;
    }
    pclose(fp);
}

void scan_wifi(char *interface) {
    wireless_scan_head head;
    wireless_scan *result;
    iwrange range;
    int sock;
    BorneWiFi bornes[MAX_BORNES];
    int count = 0;
    char current_ssid[IW_ESSID_MAX_SIZE + 1] = {0};

    get_current_ssid(current_ssid);

    sock = iw_sockets_open();

    if (iw_get_range_info(sock, interface, &range) < 0) {
        printf("Erreur lors de la récupération des informations sur la plage de fréquences pour l'interface %s.\n", interface);
        iw_sockets_close(sock);
        return;
    }

    if (iw_scan(sock, interface, range.we_version_compiled, &head) < 0) {
        printf("Erreur lors du scan sur l'interface %s.\n", interface);
        iw_sockets_close(sock);
        return;
    }

    result = head.result;
    while (result && count < MAX_BORNES) {
        strncpy(bornes[count].ssid, result->b.essid, IW_ESSID_MAX_SIZE);
        bornes[count].ssid[IW_ESSID_MAX_SIZE] = '\0';
        bornes[count].dbm = result->stats.qual.level - 256;
        memcpy(bornes[count].mac, result->ap_addr.sa_data, 6);

        if (strlen(current_ssid) == 0 || strcmp(bornes[count].ssid, current_ssid) == 0) {
            count++;
        }

        result = result->next;
    }

    qsort(bornes, count, sizeof(BorneWiFi), compare);

    for (int i = 0; i < count && i < 8; i++) {
        char *display_ssid = strlen(bornes[i].ssid) > 0 ? bornes[i].ssid : "!! caché !!";

        if (bornes[i].dbm >= -64) {
            printf("\033[32m");
        } else if (bornes[i].dbm >= -74) {
            printf("\033[33m");
        } else {
            printf("\033[31m");
        }

        printf("%-20s\n", display_ssid);

        printf("%02X:%02X:%02X:%02X:%02X:%02X %20d dBm\n",
            bornes[i].mac[0], bornes[i].mac[1], bornes[i].mac[2],
            bornes[i].mac[3], bornes[i].mac[4], bornes[i].mac[5],
            bornes[i].dbm);

        printf("\033[0m");
        printf("\n");
    }

    iw_sockets_close(sock);
}

int main() {
    char interface_wifi[16];
    
    get_wifi_interface_name(interface_wifi);
    if (strcmp(interface_wifi, "unknown") == 0) {
        printf("Aucune interface sans fil n'a été trouvée.\n");
        return 1;
    }

    while (1) {
        printf("\033[H\033[J");
        scan_wifi(interface_wifi);
        sleep(2);
    }

    return 0;
}
