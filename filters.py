def tcp_filter(frame_list, protocol):
    tcp_frame_list = [frame for frame in frame_list if frame.get_app_protocol() == protocol]
    ip_pairs_list = []
    complete_coms_dict = {}

    for frame in tcp_frame_list:
        ip_pair = (str(frame.get_src_ip()) + ":" + str(frame.get_src_port()), str(frame.get_dst_ip()) + ":"
                   + str(frame.get_dst_port()))
        if ip_pair not in ip_pairs_list and ip_pair[::-1] not in ip_pairs_list:
            ip_pairs_list.append(ip_pair)
    print(ip_pairs_list)
    ip_pair_frames = {}
    for frame in tcp_frame_list:
        ip_pair = (str(frame.get_src_ip()) + ":" + str(frame.get_src_port()), str(frame.get_dst_ip()) + ":"
                   + str(frame.get_dst_port()))
        if ip_pair in ip_pairs_list:
            if ip_pair_frames.get(ip_pair) is None:
                ip_pair_frames[ip_pair] = []
            ip_pair_frames[ip_pair] = ip_pair_frames[ip_pair] + [frame]
        elif ip_pair[::-1] in ip_pairs_list:
            if ip_pair_frames.get(ip_pair[::-1]) is None:
                ip_pair_frames[ip_pair[::-1]] = []
            ip_pair_frames[ip_pair[::-1]] = ip_pair_frames[ip_pair[::-1]] + [frame]
    k = 1
    for frames in ip_pair_frames.values():
        if ("SYN" in frames[0].get_flags() and "ACK" in frames[1].get_flags()) \
            and (("SYN" in frames[1].get_flags() and "ACK" in frames[2].get_flags())
                 or ("SYN" in frames[3].get_flags() and "ACK" in frames[4].get_flags())):
            if ("FIN" in frames[-4].get_flags() and "ACK" in frames[-1].get_flags())\
                    and (("FIN" in frames[-3].get_flags() and "ACK" in frames[-2].get_flags())
                         or ("ACK" in frames[-3].get_flags() and "FIN" in frames[-2].get_flags())):
                complete_coms_dict[f'{k:d}_0'] = frames
            elif "RST" in frames[-1].get_flags():
                complete_coms_dict[f'{k:d}_0'] = frames
            else:
                complete_coms_dict[f'{k:d}_1'] = frames
        else:
            complete_coms_dict[f'{k:d}_1'] = frames
        k += 1
    return complete_coms_dict


def tftp_filter(frame_list):
    tftp_frame_list = [frame for frame in frame_list if frame.get_app_protocol() == "TFTP"]
    ip_ports_list = []
    complete_coms_dict = {}

    for frame in tftp_frame_list:
        ip_port = (frame.get_src_ip(), frame.get_src_port())
        if ip_port not in ip_ports_list:
            ip_ports_list.append(ip_port)

    communications_frames = []
    for ip_port in ip_ports_list:
        operation_frames = [frame for frame in frame_list if ((frame.get_src_ip(), frame.get_src_port()) ==
                                                              ip_port or (
                                                              frame.get_dst_ip(), frame.get_dst_port()) == ip_port)]
        communications_frames.append(operation_frames)
    k = 1
    # TODO Double check ip_port pairs
    for frames in communications_frames:
        if frames[0].check_tftp_opcode() in ['read', 'write'] and frames[-1].check_tftp_opcode() == 'ack':
            complete_coms_dict[f'{k:d}_0'] = frames
            k += 1
        elif frames[-1].check_tftp_opcode() in ['err', 'data']:
            complete_coms_dict[f"{k:d}_1"] = frames
            k += 1
    return complete_coms_dict


def icmp_filter(frame_list):
    icmp_frame_list = [frame for frame in frame_list if frame.get_protocol() == "ICMP"]
    ip_pairs_list = []
    id_seq_list = []
    for frame in icmp_frame_list:
        ip_pair = (frame.get_src_ip(), frame.get_dst_ip())
        if ip_pair not in ip_pairs_list and ip_pair[::-1] not in ip_pairs_list:
            ip_pairs_list.append(ip_pair)
        id_seq = frame.check_icmp()
        if id_seq["id_seq"] not in id_seq_list:
            id_seq_list.append(id_seq["id_seq"])

    complete_echo_dict = {}
    k = 1
    for frame in icmp_frame_list:
        icmp_frame_info = frame.check_icmp()
        if icmp_frame_info["id_seq"] in id_seq_list and icmp_frame_info["type"] == "Request":
            id_seq = icmp_frame_info["id_seq"]
            echo = [frame]
            for frame_reply in icmp_frame_list:
                icmp_frame_info_reply = frame_reply.check_icmp()
                if icmp_frame_info_reply["id_seq"] == id_seq and icmp_frame_info_reply["type"] == "Reply":
                    echo.append(frame_reply)
                    complete_echo_dict[f"{k:d}_0"] = echo
                    k += 1
                    break
            if len(echo) == 1:
                complete_echo_dict[f"{k:d}_1"] = echo
    return complete_echo_dict


def arp_filter(frame_list):
    arp_frame_list = [frame for frame in frame_list if frame.get_ether_type() == "ARP"]
    ip_pairs_list = []
    same_ip_frame_list = []
    complete_coms = {}
    print(arp_frame_list)
    for frame in arp_frame_list:
        ip_pair = (frame.get_src_ip(), frame.get_dst_ip())
        print(ip_pair)
        if ip_pair not in ip_pairs_list and ip_pair[::-1] not in ip_pairs_list:
            ip_pairs_list.append(ip_pair)
    for ip_pair in ip_pairs_list:
        operation_frames = [frame for frame in frame_list if ((frame.get_src_ip(), frame.get_dst_ip()) == ip_pair
                                                              or (frame.get_dst_ip(), frame.get_src_ip()) == ip_pair)]
        same_ip_frame_list.append(operation_frames)
    k = 1
    print(same_ip_frame_list)
    for frames in same_ip_frame_list:
        print(frames)
        requests = 0
        replies = 0
        for frame in frames:
            print(frame.check_arp())
            if frame.check_arp() == "Request":
                requests += 1
            elif frame.check_arp() == "Reply":
                replies += 1
        if replies == requests:
            complete_coms[f"{k:d}_0"] = frames
        else:
            complete_coms[f"{k:d}_1"] = frames
        k += 1
    return complete_coms
