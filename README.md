### Prerequisites

#### Libraries and Compilation Environment
- A C compiler such as GCC.
- The `libpcap` library for packet capturing.
- Command-line utilities like `awk`, `grep`, `ping`, and `ip`, which are generally already available on Linux systems.

#### Permissions
Administrative privileges may be required for running some commands, especially those using `pcap`.

### Installation Steps

1. **GCC and libpcap**
   - On a Debian/Ubuntu machine, you can install these tools using:
        ```sh
        sudo apt-get update
        sudo apt-get install gcc libpcap-dev
        ```
   - On Red Hat/CentOS:
       ```sh
       sudo yum install gcc libpcap-devel
       ```


2. **lldpd and nmcli**
   - On a Debian/Ubuntu machine:
       ```sh
        sudo apt-get install lldpd network-manager
       ```

   - On Red Hat/CentOS:
        ```sh
        sudo yum install lldpd NetworkManager
        ```

3. **Compile the Program**
```sh
gcc discovery.c -o discovery -lpcap
```


4. **Run the Program**
```sh
chmod +x discovery
sudo ./discovery
```