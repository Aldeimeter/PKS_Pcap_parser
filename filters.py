def tcp_filter(frame_list, protocol_name):
    tcp_frame_list = [frame for frame in frame_list if frame.get_app_protocol() == protocol_name]
    ip_pairs_list = []
    coms_dict = {}
    ip_pair_frames = {}
    for frame in tcp_frame_list:
        ip_pair = (str(frame.get_src_ip()) + ":" + str(frame.get_src_port()), str(frame.get_dst_ip()) + ":"
                   + str(frame.get_dst_port()))
        if ip_pair not in ip_pairs_list and ip_pair[::-1] not in ip_pairs_list:
            ip_pairs_list.append(ip_pair)

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
        if len(frames) >= 7 and ("SYN" in frames[0].get_flags() and "ACK" in frames[1].get_flags()) \
                and (("SYN" in frames[1].get_flags() and "ACK" in frames[2].get_flags())
                     or ("SYN" in frames[3].get_flags() and "ACK" in frames[4].get_flags())):
            if ("FIN" in frames[-4].get_flags() and "ACK" in frames[-1].get_flags()) \
                    and (("FIN" in frames[-3].get_flags() and "ACK" in frames[-2].get_flags())
                         or ("ACK" in frames[-3].get_flags() and "FIN" in frames[-2].get_flags())):
                coms_dict[f'{k:d}_0'] = frames
            elif "RST" in frames[-1].get_flags():
                coms_dict[f'{k:d}_0'] = frames
            else:
                coms_dict[f'{k:d}_1'] = frames
        else:
            coms_dict[f'{k:d}_1'] = frames
        k += 1
    return coms_dict


def tftp_filter(frame_list):
    ip_pairs_list = []
    ip_pair_frames = {}
    coms_dict = {}
    udp_frame_list = [frame for frame in frame_list if frame.get_ipv4_protocol() == "UDP"]
    for i in range(len(udp_frame_list)):
        if udp_frame_list[i].get_app_protocol() == "TFTP":
            ip_pair = ()
            if udp_frame_list[i].check_tftp_opcode() == 'read':
                ip_pair = (str(udp_frame_list[i + 1].get_src_ip()) + ":" + str(udp_frame_list[i + 1].get_src_port()),
                           str(udp_frame_list[i + 1].get_dst_ip()) + ":" + str(udp_frame_list[i + 1].get_dst_port()))
            elif udp_frame_list[i].check_tftp_opcode() == 'write':
                ip_pair = (str(udp_frame_list[i + 2].get_src_ip()) + ":" + str(udp_frame_list[i + 2].get_src_port()),
                           str(udp_frame_list[i + 2].get_dst_ip()) + ":" + str(udp_frame_list[i + 2].get_dst_port()))
            if ip_pair not in ip_pairs_list:
                ip_pairs_list.append(ip_pair)
                ip_pair_frames[ip_pair] = [udp_frame_list[i]]
    for frame in udp_frame_list:
        ip_pair = (str(frame.get_src_ip()) + ":" + str(frame.get_src_port()), str(frame.get_dst_ip()) + ":"
                   + str(frame.get_dst_port()))
        if ip_pair in ip_pairs_list:
            ip_pair_frames[ip_pair] = ip_pair_frames[ip_pair] + [frame]
        elif ip_pair[::-1] in ip_pairs_list:
            ip_pair_frames[ip_pair[::-1]] = ip_pair_frames[ip_pair[::-1]] + [frame]
    k = 1
    for frames in ip_pair_frames.values():
        if frames[-1].check_tftp_opcode() in ['ack', 'err']:
            if (frames[-2].get_length() == frames[1].get_length() if frames[0].check_tftp_opcode() == "read"
                else frames[2].get_length()) \
               and frames[-2] != frames[1].get_length() if frames[0].check_tftp_opcode() == "read" \
                    else frames[2].get_length():
                coms_dict[f'{k:d}_1'] = frames
            else:
                coms_dict[f'{k:d}_0'] = frames
        else:
            coms_dict[f'{k:d}_1'] = frames
        k += 1
    return coms_dict


def icmp_filter(frame_list):
    icmp_frame_list = [frame for frame in frame_list if frame.get_ipv4_protocol() == "ICMP"]
    ip_pairs_list = []
    ip_pair_frames = {}
    coms_dict = {}
    k = 1
    frames_dict = {}
    for frame in icmp_frame_list:
        if frame.get_icmp_type() in ["Reply", "Request", "Time Exceeded"]:
            ip_pair = (
                str(frame.get_src_ip()) + ":" + frame.get_icmp_id(),
                str(frame.get_dst_ip()) + ":" + frame.get_icmp_id())
            if ip_pair not in ip_pairs_list and ip_pair[::-1] not in ip_pairs_list:
                ip_pairs_list.append(ip_pair)
        else:
            frames_dict[frame.get_number()] = [frame]
    previous_ip_pair = []
    for frame in icmp_frame_list:
        ip_pair = (
            str(frame.get_src_ip()) + ":" + frame.get_icmp_id(), str(frame.get_dst_ip()) + ":" + frame.get_icmp_id())
        if frame.get_icmp_type() == "Request":
            previous_ip_pair = ip_pair
        if frame.get_icmp_type() == "Time Exceeded" and ip_pair[1] in previous_ip_pair:
            ip_pair = previous_ip_pair
        if ip_pair in ip_pairs_list:
            if ip_pair_frames.get(ip_pair) is None:
                ip_pair_frames[ip_pair] = []
            ip_pair_frames[ip_pair] = ip_pair_frames[ip_pair] + [frame]
        elif ip_pair[::-1] in ip_pairs_list:
            if ip_pair_frames.get(ip_pair[::-1]) is None:
                ip_pair_frames[ip_pair[::-1]] = []
            ip_pair_frames[ip_pair[::-1]] = ip_pair_frames[ip_pair[::-1]] + [frame]
    for frames in ip_pair_frames.values():
        frames_dict[frames[0].get_number()] = frames
    frames_sorted_dict = {key: frames_dict[key] for key in sorted(frames_dict)}
    for frames in frames_sorted_dict.values():
        if len(frames) % 2 == 0 and frames[0].get_icmp_type() == "Request" \
                and frames[-1].get_icmp_type() in ["Reply", "Time Exceeded"]:
            coms_dict[f'{k:d}_0'] = frames
        else:
            coms_dict[f'{k:d}_1'] = frames
        k += 1
    return coms_dict


def arp_filter(frame_list):
    arp_frame_list = [frame for frame in frame_list if frame.get_ether_type() == "ARP"]
    req_dst_ip_list = []
    req_dst_ip_frames = {}
    coms_dict = {}
    for frame in arp_frame_list:
        if frame.get_arp_opcode() == "Request":
            req_dst_ip_list.append(frame.get_dst_ip())
    for frame in arp_frame_list:
        if frame.get_arp_opcode() == "Request":
            req_dst_ip = frame.get_dst_ip()
            if req_dst_ip in req_dst_ip_list:
                if req_dst_ip_frames.get(req_dst_ip) is None:
                    req_dst_ip_frames[req_dst_ip] = []
                req_dst_ip_frames[req_dst_ip] = req_dst_ip_frames[req_dst_ip] + [frame]
        elif frame.get_arp_opcode() == "Reply":
            req_dst_ip = frame.get_src_ip()
            if req_dst_ip in req_dst_ip_list:
                if req_dst_ip_frames.get(req_dst_ip) is None:
                    req_dst_ip_frames[req_dst_ip] = []
                req_dst_ip_frames[req_dst_ip] = req_dst_ip_frames[req_dst_ip] + [frame]
    k = 1
    part_com_requests = []
    opcodes = [0 for _ in range(len(req_dst_ip_frames))]
    for i, frames in enumerate(req_dst_ip_frames.values()):
        for frame in frames:
            if frame.get_arp_opcode() == "Request":
                opcodes[i] += 1
            elif frame.get_arp_opcode() == "Reply":
                opcodes[i] -= 1
    for i, frames in enumerate(req_dst_ip_frames.values()):
        if opcodes[i] < 0:
            for frame in frames:
                if frame.get_arp_opcode() == "Request":
                    frames.remove(frame)
            coms_dict[f'{k:d}_1'] = frames
            k += 1
        elif opcodes[i] >= 0:
            for frame in frames[::-1]:
                if frame.get_arp_opcode() == "Request":
                    part_com_requests.append(frame)
                    frames.remove(frame)
                elif frame.get_arp_opcode() == "Reply":
                    coms_dict[f'{k:d}_0'] = frames
                    k += 1
                    break
    if part_com_requests:
        coms_dict[f'{k:d}_1'] = part_com_requests
    return coms_dict
