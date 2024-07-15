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
#include <signal.h>
#include <time.h>

#define MAX_VLAN 4096

typedef struct {
    unsigned int id;
    char network_addr[INET_ADDRSTRLEN];
} VlanInfo;

VlanInfo found_vlans[MAX_VLAN];
int vlan_count = 0;
int vlan_found = 0;
volatile sig_atomic_t stop_program = 0;

void handle_signal(int signal) {
    stop_program = 1;
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
            if (dest == 0) {
                strcpy(interface_name, ifname);
                fclose(fp);
                return;
            }
        }
    }

    fclose(fp);
    strcpy(interface_name, "unknown");
}

void get_public_ip(char *buffer) {
    FILE *fp = popen("curl -s ifconfig.me", "r");
    if (fp != NULL) {
        fgets(buffer, 100, fp);
        strtok(buffer, "\n");
        pclose(fp);
    } else {
        strcpy(buffer, "Error");
    }
}

void get_subnet_mask(char *interface_name, char *subnet_mask, char *prefix_len_str) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip addr show %s | grep 'inet ' | awk '{print $2}'", interface_name);

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        strcpy(subnet_mask, "Error");
        return;
    }

    char buffer[256];
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        char *slash = strchr(buffer, '/');
        if (slash != NULL) {
            int prefix_len = atoi(slash + 1);
            snprintf(prefix_len_str, 4, "%d", prefix_len);

            *slash = '\0';
            struct in_addr addr;
            inet_pton(AF_INET, buffer, &addr);
            addr.s_addr = htonl(~((1 << (32 - prefix_len)) - 1));
            inet_ntop(AF_INET, &addr, subnet_mask, INET_ADDRSTRLEN);
        }
    } else {
        strcpy(subnet_mask, "Unknown");
    }
    pclose(fp);
}

void get_network_address(const char *ip, const char *netmask, char *network_address) {
    struct in_addr ip_addr, netmask_addr, subnet_addr;

    inet_pton(AF_INET, ip, &ip_addr);
    inet_pton(AF_INET, netmask, &netmask_addr);

    subnet_addr.s_addr = ip_addr.s_addr & netmask_addr.s_addr;

    inet_ntop(AF_INET, &subnet_addr, network_address, INET_ADDRSTRLEN);
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

    inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

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
            strcpy(buffer, "Unknown");
        } else {
            strtok(buffer, "\n");
        }
        pclose(fp);
    } else {
        strcpy(buffer, "Error");
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
        printf("\033[32mPing to \033[0m%s : \033[32mOK\033[0m\n", gateway);
    } else {
        printf("\033[32mPing to \033[0m%s : \033[31mFAILED\033[0m\n", gateway);
    }

    ret = system("ping -c 1 1.1.1.1 > /dev/null 2>&1");
    if (ret == 0) {
        printf("\033[32mPing to \033[0m1.1.1.1 : \033[32mOK\033[0m\n");
    } else {
        printf("\033[32mPing to \033[0m1.1.1.1 : \033[31mFAILED\033[0m\n");
    }

    ret = system("ping -c 1 google.fr > /dev/null 2>&1");
    if (ret == 0) {
        printf("\033[32mPing to \033[0mgoogle.fr : \033[32mOK\033[0m\n");
    } else {
        printf("\033[32mPing to \033[0mgoogle.fr : \033[31mFAILED\033[0m\n");
    }
}

void get_switch_port() {
    FILE *fp;
    char path[1035];

    fp = popen("lldpctl", "r");
    if (fp == NULL) {
        printf("Failed to run command.\n");
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
        return "Error running command.";
    }

    char *output = malloc(1024 * sizeof(char));
    fread(output, sizeof(char), 1024, fp);
    pclose(fp);

    return output;
}

void parse_lldp_output(char *output) {
    char *sysname = strstr(output, "SysName:");
    char *sysdescr = strstr(output, "SysDescr:");
    char *mgmtip = strstr(output, "MgmtIP:");
    char *portid = strstr(output, "PortID:");
    if (sysname) {
        sysname += strlen("SysName:");
        printf("Name :%.*s\n", strcspn(sysname, "\n"), sysname);
    }
    if (sysdescr) {
        sysdescr += strlen("SysDescr:");
        printf("Description :%.*s\n", strcspn(sysdescr, "\n"), sysdescr);
    }
    if (mgmtip) {
        mgmtip += strlen("MgmtIP:");
        printf("IP Address :%.*s\n", strcspn(mgmtip, "\n"), mgmtip);
    }
    if (portid) {
        portid += strlen("PortID:");
        printf("Port :%.*s\n", strcspn(portid, "\n"), portid);
    }
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    if (stop_program) {
        printf("\n\033[31mProgram interrupted by user.\033[0m\n");
        exit(0);
    }

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
        static int first_vlan = 1;
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

                FILE *fp = fopen("./network_info.json", "a");
                if (fp == NULL) {
                    perror("Error opening file");
                    return;
                }

                if (!first_vlan) {
                    fprintf(fp, ",\n");
                } else {
                    first_vlan = 0;
                }

                fprintf(fp, "    {\n");
                fprintf(fp, "      \"ID\": %u,\n", vlan_id);
                fprintf(fp, "      \"NetworkAddr\": \"%s\"\n", src_ip);
                fprintf(fp, "    }");

                fclose(fp);

            }
            vlan_found = 1;
            last_time = time(NULL);
        }
    }

    current_time = time(NULL);

    if (vlan_count > 0 && (current_time - last_time >= 35)) {
        FILE *fp = fopen("./network_info.json", "a");
        if (fp != NULL) {
            fprintf(fp, "\n  ]\n");
            fprintf(fp, "}\n");
            fclose(fp);
        }
        printf("\n");
        printf("\033[31mNo new VLAN found in the last 35 seconds. Stopping program.\033[0m\n");
        printf("\n");
        exit(0);
    }

    if (vlan_count == 0 && (current_time - start_time >= 60)) {
        FILE *fp = fopen("./network_info.json", "a");
        if (fp != NULL) {
            fprintf(fp, "\n  ]\n");
            fprintf(fp, "}\n");
            fclose(fp);
        }
        printf("\n");
        printf("\033[31mNo VLAN found in the first 60 seconds. Stopping program.\033[0m\n");
        printf("\n");
        exit(0);
    }
}

void save_initial_info(const char *gateway_ip, const char *dns_server, const char *dhcp_server, const char *local_network_address) {
    FILE *fp = fopen("./network_info.json", "w");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"DefaultNetwork\": {\n");
    fprintf(fp, "    \"GatewayIP\": \"%s\",\n", gateway_ip);
    fprintf(fp, "    \"DNSServer\": \"%s\",\n", dns_server);
    fprintf(fp, "    \"DHCPServer\": \"%s\",\n", dhcp_server);
    fprintf(fp, "    \"LocalNetworkAddress\": \"%s\"\n", local_network_address);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"VLANs\": [\n");
    fclose(fp);
}

void close_json_file() {
    FILE *fp = fopen("./network_info.json", "a");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }

    fprintf(fp, "\n  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
}

int main() {
    printf("\033[H\033[J");
    printf("\033[32mNetwork Information:\033[0m\n");

    signal(SIGINT, handle_signal);

    char interface_name[128];
    get_network_interface_name(interface_name);
    printf("Network Interface: %s\n", interface_name);
    if (strcmp(interface_name, "unknown") == 0) {
        printf("\033[31mNo valid network interface found. Stopping program.\033[0m\n");
        save_initial_info("", "", "", "");
        close_json_file();
        return 1;
    }

    char public_ip[100];
    get_public_ip(public_ip);
    printf("Public IP: %s\n", public_ip);

    char local_ip[100];
    get_my_ip(local_ip);
    printf("Local IP: %s\n", local_ip);

    char subnet_mask[INET_ADDRSTRLEN];
    char prefix_len_str[4];
    get_subnet_mask(interface_name, subnet_mask, prefix_len_str);

    char network_address[INET_ADDRSTRLEN];
    get_network_address(local_ip, subnet_mask, network_address);

    char network_address_with_prefix[INET_ADDRSTRLEN + 4];
    snprintf(network_address_with_prefix, sizeof(network_address_with_prefix), "%s/%s", network_address, prefix_len_str);
    printf("Network Address: %s\n", network_address_with_prefix);

    char gateway[100];
    get_default_gateway(gateway);
    printf("Default Gateway: %s\n", gateway);

    char dns_server[100];
    get_dns_server_nmcli(dns_server, interface_name);
    printf("DNS Server: %s\n", dns_server);

    char dhcp_server[100];
    get_dhcp_server(dhcp_server, interface_name);
    printf("DHCP Server: %s\n", dhcp_server);

    char *command = "lldpctl";
    char *lldp_output = run_command(command);
    printf("\n\033[32mSwitch Information:\033[0m\n");
    parse_lldp_output(lldp_output);
    free(lldp_output);

    printf("\n");
    perform_ping_tests(gateway);
    printf("\n");

    save_initial_info(gateway, dns_server, dhcp_server, network_address_with_prefix);

    char user_input;
    while (1) {
        printf("Do you want to start VLAN search (~60sec)? (y/n): ");
        user_input = getchar();
        getchar();
        if (user_input == 'y' || user_input == 'Y') {
            break;
        } else if (user_input == 'n' || user_input == 'N') {
            printf("\033[31mVLAN search canceled. Stopping program.\033[0m\n");
            close_json_file();
            return 0;
        } else {
            printf("\033[31mInvalid input. Please enter 'y' or 'n'.\033[0m\n");
        }
    }

    printf("VLAN search in progress, \033[31mplease wait\033[0m:\n");

    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "\033[31mpcap_findalldevs() failed: \033[0m%s\n", errbuf);
        close_json_file();
        return 2;
    }

    device = alldevs;
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "\033[31mCouldn't open device %s: \033[0m%s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        close_json_file();
        return 2;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "\033[31mpcap_loop() failed: \033[0m%s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        close_json_file();
        return 2;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    close_json_file();
    return 0;
}
