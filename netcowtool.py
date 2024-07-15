import subprocess
import os
import sys
from simple_term_menu import TerminalMenu

def display_options():
    options = ["discovery : simple analysis of the local network, port switch, VLANs..", "scanner : analysis and classification of hosts, use discovery first", "ssid : search and classification of the nearest ssid"]
    terminal_menu = TerminalMenu(options, title="Please select a program to run:")
    menu_entry_index = terminal_menu.show()
    if menu_entry_index is None:
        raise KeyboardInterrupt
    return str(menu_entry_index + 1)

def check_files_presence(files):
    missing_files = [file for file in files if not os.path.isfile(file)]
    return missing_files

def run_command(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while trying to run {command}: {e}")
    except FileNotFoundError:
        print(f"Command not found: {command}")
    except PermissionError:
        print(f"Permission denied: Unable to run {command}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    files = ['./discovery', './scanner', './ssid']

    while True:
        try:
            missing_files = check_files_presence(files)

            if missing_files:
                print("\033[91mSome files are missing, running setup.sh to install dependencies? (y/n)\033[0m")
                choice = input().strip().lower()
                if choice == 'y':
                    if os.path.isfile('./setup.sh'):
                        run_command("chmod +x ./setup.sh")
                        run_command("./setup.sh")
                    else:
                        print("setup.sh not found.")
                        continue
                elif choice == 'n':
                    print("Setup skipped. Exiting.")
                    break
                else:
                    print("Invalid choice. Please enter 'y' or 'n'.")
                    continue

            choice = display_options()

            commands = {
                '1': './discovery',
                '2': './scanner',
                '3': './ssid'
            }

            if choice in commands:
                try:
                    run_command(commands[choice])
                except KeyboardInterrupt:
                    print("\nProcess interrupted. Returning to menu.")
                    continue
            else:
                print("Invalid choice. Please enter a valid number (1-3).")

        except KeyboardInterrupt:
            print("\nProcess interrupted. Exiting.")
            break

if __name__ == "__main__":
    main()
