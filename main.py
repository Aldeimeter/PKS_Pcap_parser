from analyzer import print_in_yaml


def main():
    while True:
        user_input = input("Type 's' to stop the program,-p for filters or p for parsing: ").strip().lower()
        if user_input == "s":
            break
        elif user_input == '-p':
            user_input = input("""Enter one of protocols name:
            HTTP
            HTTPS
            TELNET
            SSH
            FTP-CONTROL
            FTP-DATA
            TFTP
            ICMP
            ARP\n""").strip().upper()
            if user_input in ["HTTP", "HTTPS", "TELNET", "SSH", "FTP-CONTROL", "FTP-DATA", "TFTP", "ICMP", "ARP"]:
                pcap_path = input("Enter the path to the .pcap file: ")
                print_in_yaml(pcap_path, user_input)
            else:
                print("Unknown filter")
        elif user_input == 'p':
            pcap_path = input("Enter the path to the .pcap file: ")
            print_in_yaml(pcap_path, "PARSER")


if __name__ == "__main__":
    main()
