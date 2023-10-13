from Analyzer import print_in_yaml


def main():
    while True:
        user_input = input("Type 's' to stop the program or press any key to continue: ").strip().lower()
        if user_input == "s":
            break
        else:
            user_input = input("Type -p to enter communication analysis mode or press any key to continue: ").strip()\
                .lower()
            if user_input == "-p":
                user_input = input("Enter one of protocols \
                name:\n\tHTTP\n\tHTTPS\n\tTELNET\n\tSSH\n\tFTP-CONTROL\n\tFTP-DATA\n\tTFTP\n").strip().upper()
                pcap_path = input("Enter the path to the .pcap file: ")
                print_in_yaml(pcap_path, user_input)
            else:
                pcap_path = input("Enter the path to the .pcap file: ")
                print_in_yaml(pcap_path, "parse")


if __name__ == "__main__":
    main()
