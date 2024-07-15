## Example Usage
```bash
sudo ./discovery
```
<center>
<img src="https://github.com/TheLaughingCow/discovery/blob/dev/md01.png"/>
</center>

```bash
sudo ./scanner
```
<center>
<img src="https://github.com/TheLaughingCow/discovery/blob/dev/md02.png"/>
</center>

## Prerequisites

#### Systems Tested

This setup and the corresponding scripts have been successfully tested on the following systems:

    Debian
    Kaisen Linux
    Kali Linux
    
#### Libraries and Compilation Environment

- **A C compiler such as GCC**: Essential for compiling the source code.
- **The `libpcap` library**: Required for packet capturing functionalities.
- **Command-line utilities**: Tools like `awk`, `grep`, `ping`, and `ip` are necessary and usually available on Linux systems.

#### Permissions

- **Administrative privileges**: Required for running some commands, especially those that utilize `pcap`.

## Installation Steps

Use the provided `setup.sh` script to handle all necessary installations and configurations efficiently:

```bash
sudo ./setup.sh
```
## Running the Programs

After installation, you can run the programs as follows:

```bash
sudo ./discovery
sudo ./ssid
sudo ./scanner
```
## Todo List - Future Improvements

**Python Launcher:**
Create a Python launcher with simple and multiple choice options to select the desired program to run.

**Specific Discovery Programs:**
Develop specific discovery programs to search for switches, IP phones, Windows, Linux, etc.

**Better Host Ranking in Scanner:**
Implement more sophisticated algorithms for host evaluation and ranking to enhance the accuracy and usefulness of the scanner program.

## Contributing

***/!\ All contributions are welcome /!\***

If you wish to contribute to the project, please submit your changes via pull requests on our GitHub repository.
We welcome contributions in code, documentation, testing, or any other improvements.
