### Prerequisites

#### Libraries and Compilation Environment
- A C compiler such as GCC.
- The `libpcap` library for packet capturing.
- Command-line utilities like `awk`, `grep`, `ping`, and `ip`, which are generally already available on Linux systems.

#### Permissions
Administrative privileges may be required for running some commands, especially those using `pcap`.

### Installation Steps

1. **GCC and libpcap**

```sh
# Ubuntu/Debian-based:
sudo apt-get update
sudo apt-get install gcc libpcap-dev

# Red Hat/CentOS-based:
sudo yum install gcc libpcap-devel
```


2. **lldpd and nmcli**
```sh 
# Ubuntu/Debian-based:
sudo apt-get install lldpd network-manager

# Red Hat/CentOS-based:
sudo yum install lldpd NetworkManager
```

3. **Clone the repo**
```sh 
git clone https://github.com/TheLaughingCow/discovery
cd discovery
```

4. **Compile the Program**
```sh
gcc discovery.c -o discovery -lpcap
```


5. **Run the Program**
```sh
chmod +x discovery
sudo ./discovery
```