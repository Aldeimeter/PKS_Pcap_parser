import os.path
from scapy.all import rdpcap
import ruamel.yaml as yaml
from Frame import Frame
from filters import *


def get_name(pcap_path):
    return os.path.basename(pcap_path)


def print_in_yaml(pcap_path, mode):
    try:
        packets = rdpcap("Input\\" + pcap_path)
        if len(packets) > 0:
            first_check, second_check = read_protocols()
            doc = yaml.YAML()
            header = doc.map()
            header['name'] = "PKS2023/24"
            header['pcap_name'] = get_name(pcap_path)
            complete_coms = None
            partial_coms = None
            packet_seq = doc.seq()
            index = 1
            senders = {}
            frame_list = []
            for packet in packets:
                frame = Frame(bytes(packet), index, first_check, second_check)
                frame_list.append(frame)
                if frame.get_src_ip() not in senders:
                    senders[frame.get_src_ip()] = 1
                else:
                    senders[frame.get_src_ip()] += 1
                packet_seq.append(frame.get_item())
                index += 1
            if mode == "PARSER":
                header['packets'] = packet_seq
                ipv4_senders_seq = doc.seq()
                for sender in senders.items():
                    ipv4_senders_seq.append(senders_yaml(sender))
                header['ipv4_senders'] = ipv4_senders_seq
                max_seq = doc.seq()
                max_amount = max(senders.items(), key=lambda x: x[1])[1]
                for sender in senders.items():
                    if sender[1] == max_amount:
                        max_seq.append(senders_yaml(sender))
                header['max_send_packets_by'] = max_seq
            elif mode in ["HTTP", "FTP-CONTROL", "HTTPS", "TELNET", "SSH", "FTP-DATA"]:
                complete_coms, partial_coms = communication_block(tcp_filter(frame_list, mode), mode)
            elif mode == "TFTP":
                complete_coms, partial_coms = communication_block(tftp_filter(frame_list), mode)
            elif mode == "ICMP":
                complete_coms, partial_coms = communication_block(icmp_filter(frame_list), mode)
            elif mode == "ARP":
                complete_coms, partial_coms = communication_block(arp_filter(frame_list), mode)
            if mode != "PARSER":
                header['filter_name'] = mode
                if complete_coms is not None and len(complete_coms) > 0:
                    header['complete_comms'] = complete_coms
                if partial_coms is not None and len(partial_coms) > 0:
                    header['partial_comms'] = partial_coms
            file_path = "Output\\" + mode + "\\" + get_name(pcap_path) + "_output.yaml"
            with open(file_path, "w") as yaml_file:
                doc.dump(header, yaml_file)
                return file_path
    except FileNotFoundError:
        print(f"File not found: {pcap_path}")


def senders_yaml(sender):
    nested_item = yaml.YAML()
    ipv4_sender = nested_item.map()
    ipv4_sender["node"] = sender[0]
    ipv4_sender["number_of_sent_packets"] = sender[1]
    return ipv4_sender


def read_protocols():
    with open('Protocols/PIDs.yaml', 'r') as yaml_file:
        pids = yaml.safe_load(yaml_file)
        yaml_file.close()
    with open('Protocols/SAPs.yaml', 'r') as yaml_file:
        saps = yaml.safe_load(yaml_file)
        yaml_file.close()
    with open('Protocols/Ether_types.yaml', 'r') as yaml_file:
        ether_types = yaml.safe_load(yaml_file)
        yaml_file.close()
    with open('Protocols/IPv4_protocols.yaml', 'r') as yaml_file:
        ipv4_protocols = yaml.safe_load(yaml_file)
        yaml_file.close()
    with open('Protocols/TCP_Protocol.yaml', 'r') as yaml_file:
        tcp_protocols = yaml.safe_load(yaml_file)
        yaml_file.close()
    with open('Protocols/UDP_Protocol.yaml', 'r') as yaml_file:
        udp_protocols = yaml.safe_load(yaml_file)
        yaml_file.close()
    return [pids, saps], [ether_types, ipv4_protocols, tcp_protocols, udp_protocols]


def communication_item(key, value, mode=None):
    nested_item = yaml.YAML()
    communication = nested_item.map()
    packet_seq = nested_item.seq()
    communication['number_comm'] = int(key[:len(key) - 2])
    communication['src_comm'] = value[0].get_src_ip()
    communication['dst_comm'] = value[0].get_dst_ip()
    for frame in value:
        packet_seq.append(frame.get_item(mode))
    communication['packets'] = packet_seq
    return communication


def communication_block(coms_dict, mode):
    nested_item = yaml.YAML()
    communication_seq = nested_item.seq()
    part_communication_seq = nested_item.seq()
    check = True
    for key in coms_dict.keys():
        if key[-1] == "0":
            communication_seq.append(communication_item(key, coms_dict.get(key), mode))
        elif key[-1] == "1":
            if mode not in ["ARP", "ICMP", "TFTP"] and check is True:
                check = False
            elif check is False:
                continue
            part_com_map = nested_item.map()
            part_com_map["number_comm"] = int(key[:-2])
            packet_seq = nested_item.seq()
            for frame in coms_dict.get(key):
                packet_seq.append(frame.get_item())
            part_com_map['packets'] = packet_seq
            part_communication_seq.append(part_com_map)

    return communication_seq, part_communication_seq
