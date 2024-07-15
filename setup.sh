#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Updating package lists...${NC}"
sudo apt-get update

echo -e "${GREEN}Update completed.${NC}"

echo -e "${YELLOW}Checking for curl...${NC}"
if ! command -v curl &> /dev/null; then
    echo -e "${YELLOW}Installing curl...${NC}"
    sudo apt-get install -y curl
    echo -e "${GREEN}curl installed.${NC}"
else
    echo -e "${GREEN}curl is already installed.${NC}"
fi

echo -e "${YELLOW}Installing dependencies for discovery...${NC}"
sudo apt-get install -y gcc libpcap-dev
sudo apt-get install -y lldpd network-manager
sudo systemctl start lldpd
sudo systemctl enable lldpd

echo -e "${GREEN}Dependencies for discovery installed.${NC}"

echo -e "${YELLOW}Installing dependencies for ssid...${NC}"
sudo apt-get install -y libiw-dev

echo -e "${GREEN}Dependencies for ssid installed.${NC}"

echo -e "${YELLOW}Installing dependencies for scanner...${NC}"
sudo apt-get install -y libjson-c-dev
sudo apt-get install -y macchanger
sudo apt-get install -y libxml2-dev

echo -e "${YELLOW}Checking for nmap...${NC}"
if ! command -v nmap &> /dev/null; then
    echo -e "${YELLOW}Installing nmap...${NC}"
    sudo apt-get install -y nmap
    echo -e "${GREEN}nmap installed.${NC}"
else
    echo -e "${GREEN}nmap is already installed.${NC}"
fi

echo -e "${GREEN}Dependencies for scanner installed.${NC}"

echo -e "${YELLOW}Installing simple-term-menu...${NC}"
cd /tmp
git clone https://github.com/IngoMeyer441/simple-term-menu.git
sudo mkdir -p /usr/local/lib/python3.11/dist-packages/
sudo cp /tmp/simple-term-menu/simple_term_menu.py /usr/local/lib/python3.11/dist-packages/
rm -rf /tmp/simple-term-menu
echo -e "${GREEN}simple-term-menu installed.${NC}"

echo -e "${YELLOW}Compiling programs...${NC}"
gcc ./discovery.c -o ./discovery -lpcap
gcc ./ssid.c -o ./ssid -liw
gcc ./scanner.c -o ./scanner -ljson-c `xml2-config --cflags --libs`

if [[ -f ./discovery && -f ./ssid && -f ./scanner ]]; then
    echo -e "${GREEN}The discovery, ssid, and scanner programs were successfully compiled.${NC}"
else
    echo -e "${RED}Error compiling the discovery, ssid, and scanner programs.${NC}"
    exit 1
fi

echo -e "${GREEN}Script completed. Your system is ready.${NC}"
