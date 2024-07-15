#!/bin/bash

# Définition des couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Mise à jour des listes de paquets
echo -e "${YELLOW}Mise à jour des listes de paquets...${NC}"
sudo apt-get update

echo -e "${GREEN}Mise à jour terminée.${NC}"

# Installation de curl si nécessaire
echo -e "${YELLOW}Vérification de curl...${NC}"
if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}Installation de curl...${NC}"
    sudo apt-get install -y curl
    echo -e "${GREEN}curl installé.${NC}"
else
    echo -e "${GREEN}curl est déjà installé.${NC}"
fi

# Installation des dépendances pour le programme discovery
echo -e "${YELLOW}Installation des dépendances pour discovery...${NC}"
sudo apt-get install -y gcc libpcap-dev
sudo apt-get install -y lldpd network-manager
sudo systemctl start lldpd
sudo systemctl enable lldpd

echo -e "${GREEN}Dépendances pour discovery installées.${NC}"

# Installation des dépendances pour le programme ssid
echo -e "${YELLOW}Installation des dépendances pour ssid...${NC}"
sudo apt-get install -y libiw-dev

echo -e "${GREEN}Dépendances pour ssid installées.${NC}"

# Installation des dépendances pour le programme scanner
echo -e "${YELLOW}Installation des dépendances pour scanner...${NC}"
sudo apt-get install -y libjson-c-dev
sudo apt-get install -y macchanger
sudo apt-get install -y libxml2-dev

echo -e "${YELLOW}Vérification de nmap...${NC}"
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}Installation de nmap...${NC}"
    sudo apt-get install -y nmap
    echo -e "${GREEN}nmap installé.${NC}"
else
    echo -e "${GREEN}nmap est déjà installé.${NC}"
fi

echo -e "${GREEN}Dépendances pour scanner installées.${NC}"

# Compilation des programmes
echo -e "${YELLOW}Compilation des programmes...${NC}"
gcc ./discovery.c -o ./discovery -lpcap
gcc ./ssid.c -o ./ssid -liw
gcc ./scanner.c -o ./scanner -ljson-c `xml2-config --cflags --libs`

if [[ -f ./discovery && -f ./ssid && -f ./scanner ]]; then
    echo -e "${GREEN}Les programmes discovery, ssid et scanner ont été compilés avec succès.${NC}"
else
    echo -e "${RED}Erreur lors de la compilation des programmes discovery, ssid et scanner.${NC}"
    exit 1
fi

# Fin du script
echo -e "${GREEN}Script terminé. Votre système est prêt.${NC}"
