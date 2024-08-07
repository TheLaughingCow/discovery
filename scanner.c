#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define RED     "\x1b[31m"
#define COLOR_RESET   "\x1b[0m"
#define MAX_IP_LENGTH 16
#define MAX_IPS 254
#define COMMAND_SIZE 4096
#define INITIAL_BUFFER_SIZE 52000

char interface[50];

void get_network_interface_name(char *interface_name) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        perror(RED"Erreur lors de l'ouverture de /proc/net/route"COLOR_RESET);
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

void changeMACAddressAndRenewIP(char *interface) {
    int status;
    char command[256];

    status = system("systemctl stop NetworkManager");
    if (status != 0) {
        fprintf(stderr, "Erreur lors de l'arrêt de NetworkManager\n");
        return;
    }

    sprintf(command, "dhclient -r %s", interface);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Erreur lors de la libération du bail DHCP\n");
        return;
    }

    sprintf(command, "ip addr flush dev %s", interface);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Erreur lors du flush de l'adresse IP de l'interface\n");
        return;
    }

    sprintf(command, "ip link set %s down", interface);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Erreur lors de la désactivation de l'interface réseau\n");
        return;
    }

    printf("Modification de l'adresse MAC...\n");
    sprintf(command, "macchanger -r %s > /dev/null", interface);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Erreur lors du changement d'adresse MAC\n");
        return;
    }

    sprintf(command, "ip link set %s up", interface);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Erreur lors de la réactivation de l'interface réseau\n");
        return;
    }

    sleep(2);

    sprintf(command, "dhclient %s", interface);
    status = system(command);
    if (status != 0) {
        fprintf(stderr, "Erreur lors du renouvellement du bail DHCP\n");
        return;
    }

    status = system("systemctl restart NetworkManager");
    if (status != 0) {
        fprintf(stderr, "Erreur lors du redémarrage de NetworkManager\n");
        return;
    }
}

char* getLocalNetworkAddress(char *jsonFilePath) {
    FILE *file = fopen(jsonFilePath, "r");
    if (file == NULL) {
        fprintf(stderr, RED "Erreur : pas de fichier '%s'. " COLOR_RESET "Merci d'exécuter ./discovery en premier\n", jsonFilePath);
        exit(EXIT_FAILURE);
    }

    struct json_object *parsed_json, *defaultNetwork, *localNetworkAddress;

    parsed_json = json_object_from_file(jsonFilePath);
    json_object_object_get_ex(parsed_json, "DefaultNetwork", &defaultNetwork);
    json_object_object_get_ex(defaultNetwork, "LocalNetworkAddress", &localNetworkAddress);

    char *networkAddress = strdup(json_object_get_string(localNetworkAddress));

    json_object_put(parsed_json);
    fclose(file);

    return networkAddress;
}

void scanActiveHostsAndUpdateJSON(char *network, char *jsonFilePath, int vlan_id, const char *vlanFilePath) {
    FILE *fp;
    char command[256];
    char line[1035];
    struct json_object *parsed_json, *vlans, *vlan, *activeHostsArray, *targetNetworkObject;

    sprintf(command, "nmap -sn %s | grep 'Nmap scan report for' | awk '{print $NF}' | sed 's/[()]//g'", network);
    printf(YELLOW"...Scan Nmap en cours" COLOR_RESET " reseau: "YELLOW "%s...\n" COLOR_RESET, network);

    if (vlan_id == -1) {
        parsed_json = json_object_from_file(jsonFilePath);
        if (!parsed_json) {
            parsed_json = json_object_new_object();
            json_object_object_add(parsed_json, "DefaultNetwork", json_object_new_object());
        }
        json_object_object_get_ex(parsed_json, "DefaultNetwork", &targetNetworkObject);
    } else {
        parsed_json = json_object_from_file(vlanFilePath);
        if (!parsed_json) {
            parsed_json = json_object_new_object();
            json_object_object_add(parsed_json, "VLANs", json_object_new_array());
        }
        json_object_object_get_ex(parsed_json, "VLANs", &vlans);
        
        targetNetworkObject = NULL;
        size_t vlan_count = json_object_array_length(vlans);
        for (size_t i = 0; i < vlan_count; i++) {
            vlan = json_object_array_get_idx(vlans, i);
            struct json_object *id;
            json_object_object_get_ex(vlan, "ID", &id);
            if (json_object_get_int(id) == vlan_id) {
                targetNetworkObject = vlan;
                break;
            }
        }
        if (!targetNetworkObject) {
            targetNetworkObject = json_object_new_object();
            json_object_object_add(targetNetworkObject, "ID", json_object_new_int(vlan_id));
            json_object_array_add(vlans, targetNetworkObject);
        }
    }

    json_object_object_get_ex(targetNetworkObject, "ActiveHosts", &activeHostsArray);
    if (activeHostsArray == NULL) {
        activeHostsArray = json_object_new_array();
        json_object_object_add(targetNetworkObject, "ActiveHosts", activeHostsArray);
    } else {
        struct json_object *newArray = json_object_new_array();
        json_object_object_del(targetNetworkObject, "ActiveHosts");
        json_object_object_add(targetNetworkObject, "ActiveHosts", newArray);
        activeHostsArray = newArray;
    }

    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Erreur lors de l'exécution de nmap");
        json_object_put(parsed_json);
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\n")] = 0;
        json_object_array_add(activeHostsArray, json_object_new_string(line));
    }

    pclose(fp);

    json_object_to_file((vlan_id == -1) ? jsonFilePath : vlanFilePath, parsed_json);

    json_object_put(parsed_json);

    printf(GREEN "...Scan terminé...\n" COLOR_RESET);
}

void setVLAN(char *interface, int vlan_id) {
    char command[256];
    char vlan_interface[16];

    sprintf(vlan_interface, "vlan%d", vlan_id);

    sprintf(command, "ip link delete %s", vlan_interface);
    system(command);

    sprintf(command, "ip link add link %s name %s type vlan id %d", interface, vlan_interface, vlan_id);
    system(command);

    sprintf(command, "ip link set dev %s up", vlan_interface);
    system(command);

    printf("Interface " YELLOW "VLAN %d" COLOR_RESET " configurée.\n", vlan_id);

}

void waitForDHCP(char *vlan_interface) {
    char command[256];
    
    sprintf(command, "dhclient %s", vlan_interface);
    system(command);

    sleep(2);

}

char* updateNetworkAddressForVLAN(char *vlan_interface, char *jsonFilePath, int vlan_id, int netmask_bits) {
    char command[256];
    char line[256];
    FILE *fp;
    struct in_addr ipaddr;
    char networkAddress[INET_ADDRSTRLEN];
    char networkAddressWithMask[INET_ADDRSTRLEN];

    sprintf(command, "ip addr show %s | grep 'inet '", vlan_interface);
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("Erreur lors de l'exécution de la commande");
        return NULL;
    }

    if (fgets(line, sizeof(line), fp) != NULL) {
        char addr_str[INET_ADDRSTRLEN];
        sscanf(line, " inet %[^/]/%d", addr_str, &netmask_bits);
        inet_pton(AF_INET, addr_str, &ipaddr);

        uint32_t mask = htonl(0xFFFFFFFF << (32 - netmask_bits));
        ipaddr.s_addr &= mask;
        inet_ntop(AF_INET, &ipaddr, networkAddress, INET_ADDRSTRLEN);
        sprintf(networkAddressWithMask, "%s/%d", networkAddress, netmask_bits);
    }
    pclose(fp);

    struct json_object *parsed_json, *vlans, *vlan;
    int vlan_found = 0;

    parsed_json = json_object_from_file(jsonFilePath);
    if (!json_object_object_get_ex(parsed_json, "VLANs", &vlans)) {
        vlans = json_object_new_array();
        json_object_object_add(parsed_json, "VLANs", vlans);
    }

    int vlan_count = json_object_array_length(vlans);
    for (int i = 0; i < vlan_count; i++) {
        vlan = json_object_array_get_idx(vlans, i);
        struct json_object *id;
        json_object_object_get_ex(vlan, "ID", &id);
        if (json_object_get_int(id) == vlan_id) {
            json_object_object_add(vlan, "VLANNetworkAddress", json_object_new_string(networkAddressWithMask));
            vlan_found = 1;
            break;
        }
    }

    if (!vlan_found) {
        vlan = json_object_new_object();
        json_object_object_add(vlan, "ID", json_object_new_int(vlan_id));
        json_object_object_add(vlan, "VLANNetworkAddress", json_object_new_string(networkAddressWithMask));
        json_object_array_add(vlans, vlan);
    }

    json_object_to_file(jsonFilePath, parsed_json);
    json_object_put(parsed_json);

    return strdup(networkAddressWithMask);
}

void resetNetworkInterface(char *interface) {
    char command[256];

    printf("Rétablissement de l'adresse MAC originale ...\n");
    sprintf(command, "macchanger -p %s > /dev/null", interface);
    system(command);

    sprintf(command, "ip link set %s down", interface);
    system(command);
    sprintf(command, "ip link set %s up", interface);
    system(command);

    sprintf(command, "dhclient %s", interface);
    system(command);

    system("systemctl restart NetworkManager");

    printf("Interface %s réinitialisée\n", interface);
}

void processVLANs(char *interface, char *jsonFilePath) {
    struct json_object *parsed_json, *vlans;
    int vlan_count;
    char *vlanJsonFilePath = "./network_info_vlan.json";

    parsed_json = json_object_from_file(jsonFilePath);
    if (parsed_json == NULL) {
        fprintf(stderr, "Erreur lors du chargement du fichier JSON principal.\n");
        return;
    }

    if (!json_object_object_get_ex(parsed_json, "VLANs", &vlans)) {
        fprintf(stderr, "Aucun objet 'VLANs' trouvé dans le fichier JSON.\n");
        json_object_put(parsed_json);
        return;
    }

    vlan_count = json_object_array_length(vlans);
    if (vlan_count == 0) {
        fprintf(stderr, "Le tableau de VLANs est vide.\n");
        json_object_put(parsed_json);
        return;
    }

    for (int i = 0; i < vlan_count; i++) {
        struct json_object *vlan = json_object_array_get_idx(vlans, i);
        struct json_object *id;
        if (json_object_object_get_ex(vlan, "ID", &id)) {
            int vlan_id = json_object_get_int(id);
            char vlan_interface[256];
            sprintf(vlan_interface, "vlan%d", vlan_id);

            setVLAN(interface, vlan_id);
            waitForDHCP(vlan_interface);
            char *vlan_network = updateNetworkAddressForVLAN(vlan_interface, jsonFilePath, vlan_id, 24); // Assumer un masque de sous-réseau par défaut

            if (vlan_network) {
                scanActiveHostsAndUpdateJSON(vlan_network, jsonFilePath, vlan_id, vlanJsonFilePath);
                free(vlan_network);
            }
        }
    }

    json_object_put(parsed_json);
}

void mergeAndDeleteJSONFiles(const char *filePath1, const char *filePath2, const char *mergedFilePath) {
    struct json_object *json1 = NULL, *json2 = NULL, *merged_json, *json1_vlans, *json2_vlans, *vlan;
    int i, j;

    json1 = json_object_from_file(filePath1);
    json2 = json_object_from_file(filePath2);

    if (!json1 || !json_object_object_get_ex(json1, "VLANs", &json1_vlans)) {
        json1_vlans = json_object_new_array();
        if (json1) {
            json_object_object_add(json1, "VLANs", json1_vlans);
        }
    }

    if (json2 && json_object_object_get_ex(json2, "VLANs", &json2_vlans)) {
        for (i = 0; i < json_object_array_length(json2_vlans); i++) {
            struct json_object *json2_vlan = json_object_array_get_idx(json2_vlans, i);
            int id2 = json_object_get_int(json_object_object_get(json2_vlan, "ID"));

            int found = 0;
            for (j = 0; j < json_object_array_length(json1_vlans) && !found; j++) {
                vlan = json_object_array_get_idx(json1_vlans, j);
                int id1 = json_object_get_int(json_object_object_get(vlan, "ID"));

                if (id1 == id2) {
                    json_object_object_add(vlan, "ActiveHosts", json_object_object_get(json2_vlan, "ActiveHosts"));
                    found = 1;
                }
            }
        }
    }

    merged_json = json1 ? json1 : json_object_new_object();

    if (json_object_to_file(mergedFilePath, merged_json) != 0) {
        perror("Erreur lors de l'écriture du fichier JSON fusionné");
    } else {
        printf(RED "Rapport json généré : %s\n" COLOR_RESET, mergedFilePath);
    }

    json_object_put(merged_json);
    if (json1) remove(filePath1);
    if (json2) remove(filePath2);
}

void appendToBuffer(char **buffer, const char *data, size_t *bufferSize) {
    size_t currentLength = strlen(*buffer);
    size_t dataLength = strlen(data);

    while (currentLength + dataLength >= *bufferSize) {
        *bufferSize *= 2;
        char *temp = realloc(*buffer, *bufferSize);
        if (!temp) {

            fprintf(stderr, RED"Erreur de réallocation de mémoire\n"COLOR_RESET);
            exit(1);
        }
        *buffer = temp;
    }

    strcat(*buffer, data);
}

void scanAllHostsAndSaveToXML(struct json_object *activeHosts) {
    char ipList[MAX_IPS * MAX_IP_LENGTH + 1] = "";
    size_t n_hosts = json_object_array_length(activeHosts);

    if (n_hosts > MAX_IPS) {
        printf(RED"Nombre d'hôtes trop élevé pour un scan /24. Limitation à 254 hôtes.\n"COLOR_RESET);
        n_hosts = MAX_IPS;
    }

    for (size_t i = 0; i < n_hosts; i++) {
        const char* ip = json_object_get_string(json_object_array_get_idx(activeHosts, i));
        size_t space_left = sizeof(ipList) - strlen(ipList) - 1; // -1 pour le caractère de fin de chaîne
        strncat(ipList, ip, space_left);
        if (i < n_hosts - 1) {
            strncat(ipList, " ", space_left - strlen(ip));
        }
    }

    printf(YELLOW"...Scan OS & PORTS en cours...\n"COLOR_RESET);
    char command[COMMAND_SIZE];
    snprintf(command, sizeof(command), "nmap -sS -O -F -f -T4 %s -oX ./nmap.xml > /dev/null 2>&1", ipList);

    if (system(command) != 0) {
        printf(RED "Erreur lors de l'exécution de Nmap\n"COLOR_RESET);
        return;
    }

    printf(GREEN"...Scan terminé...\n"COLOR_RESET);
}

void readXMLAndSaveToJson(const char *xmlFilePath, const char *jsonFilePath) {
    xmlDoc *doc = xmlReadFile(xmlFilePath, NULL, 0);
    if (doc == NULL) {
        return;
    }

    xmlNode *root_element = xmlDocGetRootElement(doc);
    struct json_object *jsonRoot = json_object_new_array();

    for (xmlNode *host = root_element->children; host; host = host->next) {
        if (host->type == XML_ELEMENT_NODE && strcmp((const char *)host->name, "host") == 0) {
            struct json_object *jsonHost = json_object_new_object();
            struct json_object *jsonAddress = NULL, *jsonMac = NULL, *jsonVendor = NULL, *jsonOS = NULL, *jsonHostname = NULL;
            struct json_object *jsonPortsArray = json_object_new_array();

            for (xmlNode *child = host->children; child; child = child->next) {
                if (child->type == XML_ELEMENT_NODE) {
                    if (strcmp((const char *)child->name, "address") == 0) {
                        xmlChar *addr = xmlGetProp(child, (const xmlChar *)"addr");
                        xmlChar *type = xmlGetProp(child, (const xmlChar *)"addrtype");

                        if (strcmp((const char *)type, "ipv4") == 0) {
                            jsonAddress = json_object_new_string((const char *)addr);
                        } else if (strcmp((const char *)type, "mac") == 0) {
                            jsonMac = json_object_new_string((const char *)addr);
                            xmlChar *vendor = xmlGetProp(child, (const xmlChar *)"vendor");
                            if (vendor) {
                                jsonVendor = json_object_new_string((const char *)vendor);
                                xmlFree(vendor);
                            }
                        }

                        xmlFree(addr);
                        xmlFree(type);
                    }

                    if (strcmp((const char *)child->name, "ports") == 0) {
                        for (xmlNode *port = child->children; port; port = port->next) {
                            if (port->type == XML_ELEMENT_NODE && strcmp((const char *)port->name, "port") == 0) {
                                xmlChar *portid = xmlGetProp(port, (const xmlChar *)"portid");
                                struct json_object *jsonPort = json_object_new_string((const char *)portid);
                                json_object_array_add(jsonPortsArray, jsonPort);
                                xmlFree(portid);
                            }
                        }
                    }

                    if (strcmp((const char *)child->name, "os") == 0) {
                        int max_accuracy = 0;
                        xmlChar *max_accuracy_name = NULL;

                        for (xmlNode *osmatch = child->children; osmatch; osmatch = osmatch->next) {
                            if (osmatch->type == XML_ELEMENT_NODE && strcmp((const char *)osmatch->name, "osmatch") == 0) {
                                xmlChar *name = xmlGetProp(osmatch, (const xmlChar *)"name");
                                xmlChar *accuracy = xmlGetProp(osmatch, (const xmlChar *)"accuracy");
                                int current_accuracy = atoi((const char *)accuracy);

                                if (current_accuracy > max_accuracy) {
                                    max_accuracy = current_accuracy;
                                    if (max_accuracy_name) {
                                        xmlFree(max_accuracy_name);
                                    }
                                    max_accuracy_name = xmlStrdup(name);
                                }

                                xmlFree(name);
                                xmlFree(accuracy);
                            }
                        }

                        if (max_accuracy_name && max_accuracy >= 95) {
                            char os_name[256];
                            snprintf(os_name, sizeof(os_name), "%s (%d%%)", max_accuracy_name, max_accuracy);
                            jsonOS = json_object_new_string(os_name);
                            xmlFree(max_accuracy_name);
                        } else if (max_accuracy_name) {
                            xmlFree(max_accuracy_name);
                        }
                    }

                    if (strcmp((const char *)child->name, "hostnames") == 0) {
                        jsonHostname = json_object_new_array();
                        for (xmlNode *hostnameNode = child->children; hostnameNode; hostnameNode = hostnameNode->next) {
                            if (hostnameNode->type == XML_ELEMENT_NODE && strcmp((const char *)hostnameNode->name, "hostname") == 0) {
                                xmlChar *name = xmlGetProp(hostnameNode, (const xmlChar *)"name");
                                if (name) {
                                    json_object_array_add(jsonHostname, json_object_new_string((const char *)name));
                                    xmlFree(name);
                                }
                            }
                        }
                    }
                }
            }

            if (jsonAddress != NULL) {
                json_object_object_add(jsonHost, "IP Address", jsonAddress);
            }
            if (jsonMac != NULL) {
                json_object_object_add(jsonHost, "MAC Address", jsonMac);
                if (jsonVendor != NULL) {
                    json_object_object_add(jsonHost, "Vendor", jsonVendor);
                }
            }
            if (jsonPortsArray != NULL) {
                json_object_object_add(jsonHost, "Open Ports", jsonPortsArray);
            }
            if (jsonOS != NULL) {
                json_object_object_add(jsonHost, "OS", jsonOS);
            }
            if (jsonHostname != NULL && json_object_array_length(jsonHostname) > 0) {
                json_object_object_add(jsonHost, "Hostnames", jsonHostname);
            } else if (jsonHostname != NULL) {
                json_object_put(jsonHostname);
            }

            json_object_array_add(jsonRoot, jsonHost);
        }
    }

    FILE *jsonFile = fopen(jsonFilePath, "w");
    if (jsonFile != NULL) {
        const char *jsonString = json_object_to_json_string_ext(jsonRoot, JSON_C_TO_STRING_PRETTY);
        fprintf(jsonFile, "%s", jsonString);
        fclose(jsonFile);
    }

    xmlFreeDoc(doc);
    json_object_put(jsonRoot);

    remove(xmlFilePath);
}


int MyStrcasestr(const char *haystack, const char *needle) {
    if (haystack == NULL || needle == NULL)
        return 0;

    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    if (haystack_len < needle_len)
        return 0;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (strncasecmp(haystack + i, needle, needle_len) == 0)
            return 1;
    }

    return 0;
}

void categorizeHost(const char *os_name, const char *vendor, json_object *host_json, int *hasFirewalls, int *hasServers, int *hasSwitchWifi, int *hasTelephonie, int *hasPoste, int *hasOthers, char *firewalls, char *servers, char *switchWifi, char *telephonie, char *poste, char *others, const char *hostDetails) {

    json_object *ports_obj;
    if (json_object_object_get_ex(host_json, "Open Ports", &ports_obj)) {
        size_t n_ports = json_object_array_length(ports_obj);
        for (size_t i = 0; i < n_ports; i++) {
            json_object *port = json_object_array_get_idx(ports_obj, i);
            const char *port_str = json_object_get_string(port);
            if (strstr(port_str, "5060")) {
                *hasTelephonie = 1;
                strcat(telephonie, hostDetails);
                return;
            }
        }
    }

    if ((os_name && MyStrcasestr(os_name, "firewall")) || (vendor && (MyStrcasestr(vendor, "Fortinet") || MyStrcasestr(vendor, "Sagemcom") || MyStrcasestr(vendor, "Sophos")))) {
        *hasFirewalls = 1;
        strcat(firewalls, hostDetails);
        return;
    }

    if ((vendor && MyStrcasestr(vendor, "VMware")) || (os_name && (MyStrcasestr(os_name, "ilo") || MyStrcasestr(os_name, "idrac")))) {
        *hasServers = 1;
        strcat(servers, hostDetails);
        return;
    }

    if ((os_name && MyStrcasestr(os_name, "switch")) || (vendor && (MyStrcasestr(vendor, "Aruba") || MyStrcasestr(vendor, "Unifi") || MyStrcasestr(vendor, "Zyxel") || MyStrcasestr(vendor, "Cisco") || MyStrcasestr(vendor, "Dlink") || MyStrcasestr(vendor, "Tplink") || MyStrcasestr(vendor, "Neatgear")))) {
        *hasSwitchWifi = 1;
        strcat(switchWifi, hostDetails);
        return;
    }

    json_object *hostname_obj;
    if (json_object_object_get_ex(host_json, "Hostnames", &hostname_obj)) {
        size_t n_hostnames = json_object_array_length(hostname_obj);
        for (size_t i = 0; i < n_hostnames; i++) {
            json_object *hostname = json_object_array_get_idx(hostname_obj, i);
            const char *hostname_str = json_object_get_string(hostname);
            if (MyStrcasestr(hostname_str, "esx")) {
                *hasServers = 1;
                strcat(servers, hostDetails);
                return;
            }
        }
    }

    if ((os_name && MyStrcasestr(os_name, "windows")) || (vendor && (MyStrcasestr(vendor, "HP") || MyStrcasestr(vendor, "Hewlett Packard")))) {
        json_object *os_obj = NULL;
        int isHPandPort135 = 0;

        if (vendor && (MyStrcasestr(vendor, "HP") || MyStrcasestr(vendor, "Hewlett Packard"))) {
            json_object *ports_obj;
            if (json_object_object_get_ex(host_json, "Open Ports", &ports_obj)) {
                size_t n_ports = json_object_array_length(ports_obj);
                for (size_t i = 0; i < n_ports; i++) {
                    json_object *port = json_object_array_get_idx(ports_obj, i);
                    const char *port_str = json_object_get_string(port);
                    if (strstr(port_str, "135")) {
                        isHPandPort135 = 1;
                        break;
                    }
                }
            }
        }

        if (json_object_object_get_ex(host_json, "OS", &os_obj)) {
            const char *os_name = json_object_get_string(os_obj);
            
            if ((os_name && MyStrcasestr(os_name, "windows")) || isHPandPort135) {
                *hasPoste = 1;
                strcat(poste, hostDetails);
                return;
            }
        }
    }
    
    *hasOthers = 1;
    strcat(others, hostDetails);
}


void createHtml(json_object *jsonRoot, const char *htmlFilePath) {
    char *firewalls = calloc(1, INITIAL_BUFFER_SIZE);
    char *servers = calloc(1, INITIAL_BUFFER_SIZE);
    char *switchWifi = calloc(1, INITIAL_BUFFER_SIZE);
    char *poste = calloc(1, INITIAL_BUFFER_SIZE);
    char *telephonie = calloc(1, INITIAL_BUFFER_SIZE);
    char *others = calloc(1, INITIAL_BUFFER_SIZE);
    
    if (!firewalls || !servers || !switchWifi || !poste || !telephonie || !others) {
        if (firewalls) free(firewalls);
        if (servers) free(servers);
        if (switchWifi) free(switchWifi);
        if (poste) free(poste);
        if (telephonie) free(telephonie);
        if (others) free(others);

        fprintf(stderr, RED "Erreur d'allocation de mémoire\n"COLOR_RESET);
        return;
    }

    FILE *file = fopen(htmlFilePath, "w");
    if (file == NULL) {
        fprintf(stderr, RED"Erreur lors de la création du fichier HTML\n"COLOR_RESET);
        free(firewalls);
        free(servers);
        free(switchWifi);
        free(poste);
        free(telephonie);
        free(others);
        return;
    }

    fprintf(file, "<!DOCTYPE html>\n<html lang=\"fr-FR\">");
    fprintf(file, "<meta charset=\"UTF-8\">\n");
    fprintf(file, "<title>Rapport de Scan Réseau</title>\n</head>\n");
    fprintf(file, "<style>\n");
    fprintf(file, "@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');\n");
    fprintf(file, "body { font-family: 'Roboto', sans-serif; margin: 0; padding: 0; background-color: #000; color: #fff; }\n");
    fprintf(file, ".container { width: 65%; margin: 0 auto; padding: 20px; background-color: #333; box-shadow: 0 0 20px rgba(0, 0, 0, 0.5); }\n");
    fprintf(file, "h1 { text-align: center; color: #4CAF50; }\n");
    fprintf(file, ".heart-red { color: #FF0000; }\n");
    fprintf(file, ".max-black { color: #000000; }\n");
    fprintf(file, ".firewall-container, .server-container, .switch-wifi-container, .poste-container, .telephonie-container, .other-container { margin-bottom: 20px; background-color: #222; padding: 10px; border-radius: 8px; }\n");
    fprintf(file, ".firewall-container h2, .server-container h2, .switch-wifi-container h2, .poste-container h2, .telephonie-container h2, .other-container h2 { background-color: #4CAF50; color: #000; padding: 10px; border-radius: 5px; }\n");
    fprintf(file, ".host { border: 1px solid #555; padding: 10px; margin-bottom: 10px; border-radius: 5px; background-color: #222; }\n");
    fprintf(file, ".host p { margin: 5px 0; }\n");
    fprintf(file, "a { color: #4CAF50; text-decoration: none; }\n");
    fprintf(file, "a:hover { text-decoration: underline; color: #FFF; }\n");
    fprintf(file, "@media print { .container { width: 100%; } }\n");
    fprintf(file, ".accordion { cursor: pointer; width: 100%; border: none; text-align: left; outline: none; font-size: 20px; transition: 0.4s; }\n");
    fprintf(file, ".panel { display: none; overflow: hidden; }\n");
    fprintf(file, "</style>\n");
    fprintf(file, "<body>\n");
    fprintf(file, "<script src='https://code.jquery.com/jquery-3.5.1.min.js'></script>\n");
    fprintf(file, "<script>\n");
    fprintf(file, "$(document).ready(function(){\n");
    fprintf(file, "  $('.accordion').click(function(){\n");
    fprintf(file, "    this.classList.toggle('active');\n");
    fprintf(file, "    var panel = this.nextElementSibling;\n");
    fprintf(file, "    if (panel.style.display === 'block') {\n");
    fprintf(file, "      panel.style.display = 'none';\n");
    fprintf(file, "    } else {\n");
    fprintf(file, "      panel.style.display = 'block';\n");
    fprintf(file, "    }\n");
    fprintf(file, "  });\n");
    fprintf(file, "});\n");
    fprintf(file, "</script>\n");
    fprintf(file, "<div class='container'>\n");
    fprintf(file, "<h1>Scan Réseau by <span class='max-black'>MAX</span> made with <span class='heart-red'>♥</span></h1>\n");

    int hasFirewalls = 0, hasServers = 0, hasSwitchWifi = 0, hasPoste = 0, hasTelephonie = 0, hasOthers = 0; 

    size_t n_hosts = json_object_array_length(jsonRoot);
    for (size_t i = 0; i < n_hosts; i++) {
        json_object *host = json_object_array_get_idx(jsonRoot, i);

        json_object *ip_addr_obj, *os_obj, *vendor_obj, *mac_obj, *ports_obj, *hostname_obj;
        const char *ip_addr, *os_name = NULL, *vendor = NULL, *mac = NULL;
        int os_accuracy = -1;
        int webPort = -1;

        json_object_object_get_ex(host, "IP Address", &ip_addr_obj);
        json_object_object_get_ex(host, "OS", &os_obj);
        json_object_object_get_ex(host, "Vendor", &vendor_obj);
        json_object_object_get_ex(host, "MAC Address", &mac_obj);
        json_object_object_get_ex(host, "Open Ports", &ports_obj);
        json_object_object_get_ex(host, "Hostnames", &hostname_obj);

        ip_addr = json_object_get_string(ip_addr_obj);
        vendor = json_object_get_string(vendor_obj);
        mac = json_object_get_string(mac_obj);
        os_name = json_object_get_string(os_obj);

        if (os_obj) {
            json_object *os_name_obj, *os_accuracy_obj;
            json_object_object_get_ex(os_obj, "Name", &os_name_obj);
            json_object_object_get_ex(os_obj, "Accuracy", &os_accuracy_obj);

            if (os_name_obj) {
                os_name = json_object_get_string(os_name_obj);
            }

            if (os_accuracy_obj) {
                os_accuracy = json_object_get_int(os_accuracy_obj);
            }
        }

        if (ports_obj) {
            size_t n_ports = json_object_array_length(ports_obj);
            for (size_t j = 0; j < n_ports; j++) {
                int port = atoi(json_object_get_string(json_object_array_get_idx(ports_obj, j)));
                if (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 4444) {
                    webPort = port;
                    break;
                }
            }
        }

        char hostDetails[1024]; 
        int length = 0;

        length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<div class='host'>\n");
        
        if (webPort != -1) {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<div class='accordion'>IP Address: <a href='http://%s:%d' target='_blank'>%s</a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s</div>", ip_addr, webPort, ip_addr, vendor);
        } else {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<div class='accordion'>IP Address: %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s</div>\n", ip_addr, vendor);

        }
        
        length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<div class='panel'>\n");

        if (os_name && os_accuracy >= 0) {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<p>OS: %s %d%%<br>MAC Address: %s", os_name, os_accuracy, mac);
        } else {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<p>OS: %s<br>MAC Address: %s", os_name, mac);
        }

        if (ports_obj && json_object_array_length(ports_obj) > 0) {
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "<br>Open Ports: ");

            size_t n_ports = json_object_array_length(ports_obj);
            for (size_t j = 0; j < n_ports; j++) {
                if (length < sizeof(hostDetails)) {
                    length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "%s", json_object_get_string(json_object_array_get_idx(ports_obj, j)));
                    if (j < n_ports - 1) {
                        length += snprintf(hostDetails + length, sizeof(hostDetails) - length, ", ");
                    }
                }
            }
            length += snprintf(hostDetails + length, sizeof(hostDetails) - length, "\n");
        }

        hostDetails[sizeof(hostDetails) - 1] = '\0';

        if (hostname_obj && json_object_array_length(hostname_obj) > 0) {
            strcat(hostDetails, "<br>Hostnames: ");
            size_t n_hostnames = json_object_array_length(hostname_obj);
            for (size_t j = 0; j < n_hostnames; j++) {
                strcat(hostDetails, json_object_get_string(json_object_array_get_idx(hostname_obj, j)));
                if (j < n_hostnames - 1) {
                    strcat(hostDetails, ", ");
                }
            }
            strcat(hostDetails, "</p>\n");
        }

        strcat(hostDetails, "</div>\n</div>\n");

        categorizeHost(os_name, vendor, host, &hasFirewalls, &hasServers, &hasSwitchWifi, &hasTelephonie, &hasPoste, &hasOthers, firewalls, servers, switchWifi, telephonie, poste, others, hostDetails);

    }

    if (hasFirewalls) {
        fprintf(file, "<div class='firewall-container'><h2>Firewalls</h2>\n%s</div>\n", firewalls); 
    }
    if (hasServers) {
        fprintf(file, "<div class='server-container'><h2>Serveurs</h2>\n%s</div>\n", servers);
    }
    if (hasSwitchWifi) {
        fprintf(file, "<div class='switch-wifi-container'><h2>Switch & Wifi</h2>\n%s</div>\n", switchWifi);
    }
    if (hasPoste) {
        fprintf(file, "<div class='poste-container'><h2>Postes</h2>\n%s</div>\n", poste);
    }
    
    if (hasTelephonie) {
        fprintf(file, "<div class='telephonie-container'><h2>Téléphonie</h2>\n%s</div>\n", telephonie);
    }
    if (hasOthers) {
        fprintf(file, "<div class='other-container'><h2>Autre</h2>\n%s</div>\n", others);
    }

    fprintf(file, "</div>\n</body>\n</html>"); 
    fclose(file);

    free(firewalls);
    free(servers);
    free(switchWifi);
    free(poste);
    free(telephonie);
    free(others);

    printf(RED "Rapport HTML généré. %s\n" COLOR_RESET, htmlFilePath);
}

void signalHandler(int signum) {
    printf(RED"Interruption détectée." COLOR_RESET "Réinitialisation du réseau...\n");
    resetNetworkInterface(interface);
        printf(RED "Fin du programme\n" COLOR_RESET);
    exit(signum);
}

void cleanup() {
    resetNetworkInterface(interface);
        printf(RED "Fin du programme\n" COLOR_RESET);
}

int main() {

    printf("\033[H\033[J");
    char *jsonFilePath = "./network_info.json";
    char *vlanJsonFilePath = "./network_info_vlan.json";

    get_network_interface_name(interface);

    signal(SIGINT, signalHandler);
    atexit(cleanup);
    printf(GREEN "Interface réseau :" COLOR_RESET " %s\n", interface);

    changeMACAddressAndRenewIP(interface);
    char* networkAddress = getLocalNetworkAddress(jsonFilePath);
    
    scanActiveHostsAndUpdateJSON(networkAddress, jsonFilePath, -1, vlanJsonFilePath);

    free(networkAddress);

    processVLANs(interface, jsonFilePath);

    mergeAndDeleteJSONFiles("./network_info.json", "./network_info_vlan.json", "./network.json");

    changeMACAddressAndRenewIP(interface);

    struct json_object *parsed_json, *defaultNetwork, *activeHosts;
    printf("Début du Scan DefaultNetwork & création du raport\n");

    parsed_json = json_object_from_file("./network.json");
    if (parsed_json == NULL) {
        fprintf(stderr, RED"Erreur: Impossible de lire ./network.json\n"COLOR_RESET);
        return 1;
    }

    if (!json_object_object_get_ex(parsed_json, "DefaultNetwork", &defaultNetwork)) {
        fprintf(stderr, RED "Erreur: 'DefaultNetwork' non trouvé dans le JSON\n"COLOR_RESET);
        json_object_put(parsed_json);
        return 1;
    }

    if (!json_object_object_get_ex(defaultNetwork, "ActiveHosts", &activeHosts)) {
        fprintf(stderr, RED "Erreur: 'ActiveHosts' non trouvé dans 'DefaultNetwork'\n"COLOR_RESET);
        json_object_put(parsed_json);
        return 1;
    }

    if (!json_object_is_type(activeHosts, json_type_array)) {
        fprintf(stderr, RED "Erreur: 'ActiveHosts' n'est pas un tableau JSON\n"COLOR_RESET);
        json_object_put(parsed_json);
        return 1;
    }

    scanAllHostsAndSaveToXML(activeHosts);

    readXMLAndSaveToJson("./nmap.xml", "./nmap.json");

    json_object_put(parsed_json);

    struct json_object *jsonRoot = json_object_from_file("./nmap.json");
    if (jsonRoot == NULL) {
        fprintf(stderr, RED "Erreur: Impossible de lire ./nmap.json\n" COLOR_RESET);
        return 1;
    }

    if (!json_object_is_type(jsonRoot, json_type_array)) {
        fprintf(stderr, RED "Erreur: Le contenu JSON n'est pas un tableau\n" COLOR_RESET);
        json_object_put(jsonRoot);
        return 1;
    }

    createHtml(jsonRoot, "./rapport.html");

    json_object_put(jsonRoot);

    return 0;
}
