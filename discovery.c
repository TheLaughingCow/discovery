#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <time.h>

#define MAX_VLAN 4096

typedef struct {
    unsigned int id;
    char network_addr[INET_ADDRSTRLEN];
} VlanInfo;

VlanInfo found_vlans[MAX_VLAN];
int vlan_count = 0;

void print_banner() {
    printf("    ____  _                                          \n");
    printf("   / __ \\(_)_____________ _   _____  _______  __    \n");
    printf("  / / / / / ___/ ___/ __ \\ | / / _ \\/ ___/ / / /   \n");
    printf(" / /_/ / (__  ) /__/ /_/ / |/ /  __/ /  / /_/ /      \n");
    printf("/_____/_/____/\\___/\\____/|___/\\___/_/   \\__, /   \n");
    printf("                                       /____/        \n");

}

void get_network_interface_name(char *interface_name) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        strcpy(interface_name, "unknown");
        return;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char ifname[16];
        unsigned long dest;
        
        if (sscanf(line, "%s\t%lX", ifname, &dest) == 2) {
            if (dest == 0) { // Route par défaut
                strcpy(interface_name, ifname);
                fclose(fp);
                return;
            }
        }
    }
    
    fclose(fp);
    strcpy(interface_name, "unknown");
}

void get_my_ip(char *buffer) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    const char* dest = "8.8.8.8";
    uint16_t port = 53;

    struct sockaddr_in serv;
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(dest);
    serv.sin_port = htons(port);

    connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    getsockname(sock, (struct sockaddr*) &name, &namelen);

    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    close(sock);
}

void get_default_gateway(char *buffer) {
    FILE *fp = popen("ip route | grep default | awk '{print $3}'", "r");
    if (fp != NULL) {
        fgets(buffer, 100, fp);
        strtok(buffer, "\n");
        pclose(fp);
    }
}

void get_dhcp_server(char *buffer, const char *interface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nmcli -f DHCP4.OPTION device show %s | grep dhcp_server_identifier | awk -F '=' '{print $2}'", interface);

    
    FILE *fp = popen(cmd, "r");
    if (fp != NULL) {
        if (fgets(buffer, 100, fp) == NULL) {
            strcpy(buffer, "Inconnu");
        } else {
            strtok(buffer, "\n");
        }
        pclose(fp);
    } else {
        strcpy(buffer, "Erreur");
    }
}

void get_dns_server_nmcli(char *buffer, const char *interface_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nmcli -t -f IP4.DNS device show %s | cut -d: -f2", interface_name);
    
    FILE *fp = popen(cmd, "r");
    if (fp != NULL) {
        fgets(buffer, 100, fp);
        strtok(buffer, "\n");
        pclose(fp);
    }
}

void perform_ping_tests(const char *gateway) {
    char cmd[256];
    int ret;

    
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s > /dev/null 2>&1", gateway);
    ret = system(cmd);
    if (ret == 0) {
        printf("\033[32mPing vers \033[34m%s\033[0m : \033[32mOK\033[0m\n", gateway);
    } else {
        printf("\033[32mPing vers \033[34m%s\033[0m : \033[31mFAILED\033[0m\n", gateway);
    }

    
    ret = system("ping -c 1 1.1.1.1 > /dev/null 2>&1");
    if (ret == 0) {
        printf("\033[32mPing vers \033[34m1.1.1.1\033[0m : \033[32mOK\033[0m\n");
    } else {
        printf("\033[32mPing vers \033[34m1.1.1.1\033[0m : \033[31mFAILED\033[0m\n");
    }

   
    ret = system("ping -c 1 google.fr > /dev/null 2>&1");
    if (ret == 0) {
        printf("\033[32mPing vers \033[34mgoogle.fr\033[0m : \033[32mOK\033[0m\n");
    } else {
        printf("\033[32mPing vers \033[34mgoogle.fr\033[0m : \033[31mFAILED\033[0m\n");
    }
}

void get_switch_port() {
    FILE *fp;
    char path[1035];

    fp = popen("lldpctl", "r");
    if (fp == NULL) {
        printf("Échec de l'exécution de la commande.\n");
        exit(1);
    }

    while (fgets(path, sizeof(path), fp) != NULL) {
        printf("%s", path);
    }

    pclose(fp);
}

char *run_command(const char *command) {
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        return "Erreur lors de l'exécution de la commande.";
    }

    char *output = malloc(1024 * sizeof(char));
    fread(output, sizeof(char), 1024, fp);
    pclose(fp);

    return output;
}

void parse_lldp_output(char *output) {
    char *sysname = strstr(output, "SysName: ");
    char *sysdescr = strstr(output, "SysDescr: ");
    char *mgmtip = strstr(output, "MgmtIP: ");
    char *portid = strstr(output, "PortID: ");
    if (sysname) {
        sysname += strlen("SysName: ");
        printf("\033[34mNom :\033[0m %.*s\n", strcspn(sysname, "\n"), sysname);
    }
    if (sysdescr) {
        sysdescr += strlen("SysDescr: ");
        printf("\033[34mDescription :\033[0m %.*s\n", strcspn(sysdescr, "\n"), sysdescr);
    }
    if (mgmtip) {
        mgmtip += strlen("MgmtIP: ");
        printf("\033[34mAdresse IP :\033[0m %.*s\n", strcspn(mgmtip, "\n"), mgmtip);
    }
    if (portid) {
        portid += strlen("PortID: ");
        printf("\033[34mPort :\033[0m %.*s\n", strcspn(portid, "\n"), portid);
    }
}


void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static time_t last_time = 0;  
    static time_t start_time = 0; 
    static int first_call = 1;    
    time_t current_time;

    if (first_call) {
        start_time = time(NULL);
        first_call = 0;
    }

    struct ether_header *eth_header;
    struct ip *ip_header;

    eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_VLAN) {
        unsigned int vlan_tag = (unsigned int) ntohs(*(unsigned short *)(packet + 14));
        unsigned int vlan_id = vlan_tag & 0x0FFF;

        int found = 0;
        for (int i = 0; i < vlan_count; ++i) {
            if (found_vlans[i].id == vlan_id) {
                found = 1;
                break;
            }
        }

        if (!found) {
            if (pkthdr->len >= 18 + sizeof(struct ip)) {
                ip_header = (struct ip *)(packet + 18);
                char src_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

                found_vlans[vlan_count].id = vlan_id;
                snprintf(found_vlans[vlan_count].network_addr, INET_ADDRSTRLEN, "%s", src_ip);
                ++vlan_count;

                printf("\033[33mVLAN ID:\033[0m %u\n", vlan_id);

            }
           
            last_time = time(NULL);
        }
    }

    current_time = time(NULL);


    if (vlan_count > 0 && (current_time - last_time >= 35)) {
        printf("\n");
        printf("\033[31mAucun nouveau VLAN trouvé pendant les dernières 35 secondes. Arrêt du programme.\033[0m\n");
        printf("\n");
        exit(0);
    }


    if (vlan_count == 0 && (current_time - start_time >= 60)) {
        printf("\n");
        printf("\033[31mAucun VLAN trouvé pendant les premières 60 secondes. Arrêt du programme.\033[0m\n");
        printf("\n");
        exit(0);
    }
}

int main() {
    printf("\033[H\033[J");
    print_banner();
    printf("\n");
    printf("\033[31m*****************************************************\033[0m");
    printf("\n");
    
    char interface_name[128];
    get_network_interface_name(interface_name);
    printf("\033[32mNom de l'interface réseau :\033[0m %s\n", interface_name);

    if (strcmp(interface_name, "unknown") == 0) {
        printf("\033[31mAucune interface réseau valide trouvée. Arrêt du programme.\033[0m\n");
        return 1;
    }

    char buffer[100];
    get_my_ip(buffer);
    printf("\n");
    printf("\033[32mMon adresse IP est :\033[0m %s\n", buffer);
    printf("\n");

    char gateway[100];
    get_default_gateway(gateway);
    printf("\033[32mPasserelle par défaut :\033[0m %s\n", gateway);
    printf("\n");

    char dns_server[100];
    get_dns_server_nmcli(dns_server, interface_name);
    printf("\033[32mServeur DNS :\033[0m %s\n", dns_server);
    printf("\n");

    char dhcp_server[100];
    get_dhcp_server(dhcp_server, interface_name);
    printf("\033[32mServeur DHCP :\033[0m %s\n", dhcp_server);
    printf("\n");

    char *command = "lldpctl";
    char *lldp_output = run_command(command);

    printf("\n");
    printf("\033[31m*****************************************************\033[0m");
    printf("\n");
    printf("\n");
    printf("\033[32mInformations du SWITCH :\033[0m\n");
    printf("\n");
    parse_lldp_output(lldp_output);

    free(lldp_output);
    printf("\n");
    printf("\033[31m*****************************************************\033[0m");
    printf("\n");
    printf("\n");
    perform_ping_tests(gateway);
    printf("\n");
    printf("\033[31m*****************************************************\033[0m");
    printf("\n");
    printf("\n\033[32mRecherche de VLANS en cours, merci de patienter (~35sec), stop (>60sec):\033[0m\n");
    printf("\n");
    
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "\033[31mpcap_loop() failed :\033[0m %s\n", pcap_geterr(handle));
        return 2;
    }

    device = alldevs;
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "\033[31mCouldn't open device\033[0m %s : %s\n", device->name, errbuf);
        return 2;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "\033[31mCouldn't find default device :\033[0m %s\n", errbuf);
        return 2;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
