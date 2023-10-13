import ruamel.yaml as yaml
from ruamel.yaml.scalarstring import LiteralScalarString


class Frame:
    def __init__(self, byte_code, number, first_check, second_check):
        self._byte_code = byte_code
        self._length = len(byte_code)
        if self._length < 60:
            self._medium_length = 64
        else:
            self._medium_length = self._length + 4
        self._number = number
        self._destination = self.get_destination_from_byte_code()
        self._source = self.get_source_from_byte_code()
        self._frame_type, self._sap, self._pid = self.check_type(first_check)
        if self._frame_type == "Ethernet II":
            self._ether_type, self._ipv4_protocol, self._source_ip, self._destination_ip, \
                self._source_port, self._destination_port, self._app_protocol = self.ether_type_check(second_check)
            if self._app_protocol in ["HTTP", "FTP-CONTROL", "HTTPS", "TELNET", "SSH", "FTP-DATA"]:
                self._flags = self.check_flags()
        self._hex_code = self.create_hex_code()

    def get_length(self):
        return self._length

    def get_protocol(self):
        if self._frame_type == "Ethernet II" and self._ether_type == "IPv4":
            return self._ipv4_protocol

    def get_src_port(self):
        return self._source_port

    def get_dst_port(self):
        return self._destination_port

    def get_src_ip(self):
        if self._frame_type == "Ethernet II" and (self._ether_type =="IPv4" or self._ether_type == "ARP"):
            return self._source_ip

    def get_dst_ip(self):
        if self._frame_type == "Ethernet II" and (self._ether_type =="IPv4" or self._ether_type == "ARP"):
            return self._destination_ip

    def get_app_protocol(self):
        if self._frame_type == "Ethernet II" and self._ether_type == "IPv4":
            return self._app_protocol

    def get_flags(self):
        return self._flags

    def get_number(self):
        return self._number

    def get_destination_from_byte_code(self):
        destination = ""
        for byte in self._byte_code[0:6]:
            destination += f"{byte:02x}" + ":"
        return destination.upper()[0:len(destination) - 1]

    def get_source_from_byte_code(self):
        destination = ""
        for byte in self._byte_code[6:12]:
            destination += f"{byte:02x}" + ":"
        return destination.upper()[0:len(destination) - 1]

    def check_type(self, first_check):
        checker = ""
        for byte in self._byte_code[12:14]:
            checker += f"{byte:02x}"
        if int(checker, 16) <= 1500:
            checker = f"{self._byte_code[14]:02x}"
            if checker == "ff":
                checker += f"{self._byte_code[15]:02x}"
                if checker == "ffff":
                    return "IEEE 802.3 RAW", None, None
            elif checker == "aa":
                for byte in self._byte_code[15:17]:
                    checker += f"{byte:02x}"
                if checker == "aaaa03":
                    checker = ""
                    for byte in self._byte_code[20:22]:
                        checker += f"{byte:02x}"
                    return "IEEE 802.3 LLC & SNAP", None, first_check[0].get(checker)
            checker = f"{self._byte_code[14]:02x}"
            return "IEEE 802.3 LLC", first_check[1].get(checker), None
        return "Ethernet II", None, None

    def ether_type_check(self, second_check):
        checker = ""
        for byte in self._byte_code[12:14]:
            checker += f"{byte:02x}"
        ether_type = second_check[0].get(checker)
        checker = ""
        for byte in self._byte_code[26:30]:
            checker += f'{byte:d}.'
        source_ip = checker[:len(checker) - 1]
        checker = ""
        for byte in self._byte_code[30:34]:
            checker += f'{byte:d}.'
        destination_ip = checker[:len(checker) - 1]
        if ether_type == "IPv4":
            ipv4_protocol = second_check[1][f'{self._byte_code[23]:02x}']
            if ipv4_protocol == "UDP" or "TCP":
                checker = ""
                for byte in self._byte_code[34:36]:
                    checker += f'{byte:02x}'
                source_port = int(checker, 16)
                checker = ""
                for byte in self._byte_code[36:38]:
                    checker += f'{byte:02x}'
                destination_port = int(checker, 16)
                if ipv4_protocol == 'TCP':
                    app_protocol = second_check[2].get(int(source_port), None)
                    if app_protocol is None:
                        app_protocol = second_check[2].get(int(destination_port), None)
                else:
                    app_protocol = second_check[3].get(source_port, None)
                    if app_protocol is None:
                        app_protocol = second_check[3].get(destination_port, None)
                return ether_type, ipv4_protocol, source_ip, destination_ip, source_port, destination_port, app_protocol
        elif ether_type == "ARP":
            checker = ""
            for byte in self._byte_code[28:32]:
                checker += f'{byte:d}.'
            source_ip = checker[:len(checker) - 1]
            checker = ""
            for byte in self._byte_code[38:42]:
                checker += f'{byte:d}.'
            destination_ip = checker[:len(checker) - 1]
        return ether_type, None, source_ip, destination_ip, None, None, None

    def create_hex_code(self):
        hex_code = ""
        for i in range(0, len(self._byte_code)):
            hex_code += f"{self._byte_code[i]:02x}" + "\n" if (i + 1) % 16 == 0 and i != 0 and i != len(
                self._byte_code) else f"{self._byte_code[i]:02x}" + " "
        return hex_code.upper().strip() + "\n"

    def check_flags(self):
        checker = ""
        for byte in self._byte_code[46:48]:
            checker += f'{byte:02x}'
        flag_bits = bin(int(checker[1:], 16))[2:]
        flag_bits = flag_bits.zfill(12)
        flags = []
        if flag_bits[7] == '1':
            flags.append("ACK")
        if flag_bits[8] == '1':
            flags.append("PUSH")
        if flag_bits[9] == '1':
            flags.append("RST")
        if flag_bits[10] == '1':
            flags.append("SYN")
        if flag_bits[11] == '1':
            flags.append("FIN")
        return flags

    def check_tftp_opcode(self):
        checker = ""
        for byte in self._byte_code[42:44]:
            checker += f'{byte:02x}'
        tftp_opcodes = {
            '0001': 'read',
            '0002': 'write',
            '0003': 'data',
            '0004': 'ack',
            '0005': 'err'
        }
        return tftp_opcodes[checker]

    def check_icmp(self):
        checker = ""
        icmp_types = {
            "00": "Reply",
            "08": "Request"
        }
        offset = int(f"{self._byte_code[17]:02x}", 16) - 96
        for byte in self._byte_code[74+offset:76+offset]:
            checker += f'{byte:02x}'
        id_seq = str(int(checker, 16))
        checker = ""
        for byte in self._byte_code[76+offset:78+offset]:
            checker += f'{byte:02x}'
        id_seq += "_" + str(int(checker, 16))
        return {"type": icmp_types.get(f'{self._byte_code[70+offset]:02x}'), "id_seq": id_seq}

    def check_arp(self):
        checker = ""
        for byte in self._byte_code[20:22]:
            checker += f'{byte:02x}'
        return {"0001": "Request", "0002": "Reply"}.get(checker)

    def get_ether_type(self):
        if self._frame_type == "Ethernet II":
            return self._ether_type

    def get_item(self):
        nested_item = yaml.YAML()
        packet = nested_item.map()
        packet["frame_number"] = self._number
        packet["len_frame_pcap"] = self._length
        packet["len_frame_medium"] = self._medium_length
        packet["frame_type"] = self._frame_type
        packet["src_mac"] = self._source
        packet["dst_mac"] = self._destination
        if self._sap is not None:
            packet["sap"] = self._sap
        if self._pid is not None:
            packet["pid"] = self._pid
        if self._frame_type == "Ethernet II":
            if self._ether_type is not None:
                packet["ether_type"] = self._ether_type
            if self._source_ip is not None:
                packet["src_ip"] = self._source_ip
            if self._destination_ip is not None:
                packet["dst_ip"] = self._destination_ip
            if self._ipv4_protocol is not None:
                packet["protocol"] = self._ipv4_protocol
            if self._ipv4_protocol == "TCP" or self._ipv4_protocol == "UDP":
                if self._source_port is not None:
                    packet["src_port"] = self._source_port
                if self._destination_port is not None:
                    packet["dst_port"] = self._destination_port
                if self._app_protocol is not None:
                    packet["app_protocol"] = self._app_protocol
        packet["hexa_frame"] = LiteralScalarString("".join(self._hex_code))
        return packet
