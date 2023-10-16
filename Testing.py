import unittest
from analyzer import print_in_yaml
from validator import validate

data = {
    'http': [
        'trace_ip_nad_20_B.pcap',
        'trace-1.pcap',
        'trace-10.pcap',
        'trace-11.pcap',
        'trace-12.pcap',
        'trace-14.pcap',
        'trace-20.pcap',
        'trace-21.pcap',
        'trace-24.pcap',
        'trace-25.pcap',
        'trace-27.pcap',
        'trace-3.pcap',
        'trace-4.pcap',
        'trace-6.pcap',
        'trace-8.pcap',
        'trace-9.pcap',
    ],
    'https': [
        'trace-10.pcap',
        'trace-12.pcap',
        'trace-14.pcap',
        'trace-17.pcap',
        'trace-27.pcap',
        'trace-8.pcap',
    ],
    'telnet': [
        'eth-6.pcap',
        'eth-7.pcap',
        'trace-14.pcap',
        'trace-19.pcap',
        'trace-9.pcap',
    ],
    'ssh': [
        'eth-5.pcap',
        'trace-18.pcap',
    ],
    'tftp': [
        'eth-8.pcap',
        'eth-9.pcap',
        'trace-15.pcap',
    ],
    'ftp-control': [
        'eth-4.pcap',
        'trace-12.pcap',
        'trace-13.pcap',
        'trace-14.pcap',
        'trace-16.pcap',
        'trace-6.pcap',
        'trace-7.pcap',
        'trace-8.pcap',
    ],
    'ftp-data': [
        'eth-4.pcap',
        'trace-12.pcap',
        'trace-13.pcap',
        'trace-14.pcap',
        'trace-16.pcap',
        'trace-6.pcap',
        'trace-7.pcap',
        'trace-8.pcap',
    ],
    'arp': [
        'eth-4.pcap',
        'eth-8.pcap',
        'trace-1.pcap',
        'trace-10.pcap',
        'trace-11.pcap',
        'trace-12.pcap',
        'trace-13.pcap',
        'trace-14.pcap',
        'trace-15.pcap',
        'trace-2.pcap',
        'trace-20.pcap',
        'trace-21.pcap',
        'trace-22.pcap',
        'trace-23.pcap',
        'trace-24.pcap',
        'trace-25.pcap',
        'trace-26.pcap',
        'trace-27.pcap',
        'trace-8.pcap',
    ],
    'icmp': [
        'eth-9.pcap',
        'trace_ip_nad_20_B.pcap',
        'trace-15.pcap',
        'trace-26.pcap',
        'trace-27.pcap',
        'trace-6.pcap',
    ]
}


class TestHttp(unittest.TestCase):
    def test_http_1(self):
        result = validate(print_in_yaml(data["http"][0], "HTTP"))
        self.assert_(result, True)

    def test_http_2(self):
        result = validate(print_in_yaml(data["http"][1], "HTTP"))
        self.assert_(result, True)

    def test_http_3(self):
        result = validate(print_in_yaml(data["http"][2], "HTTP"))
        self.assert_(result, True)

    def test_http_4(self):
        result = validate(print_in_yaml(data["http"][3], "HTTP"))
        self.assert_(result, True)

    def test_http_5(self):
        result = validate(print_in_yaml(data["http"][4], "HTTP"))
        self.assert_(result, True)

    def test_http_6(self):
        result = validate(print_in_yaml(data["http"][5], "HTTP"))
        self.assert_(result, True)

    def test_http_7(self):
        result = validate(print_in_yaml(data["http"][6], "HTTP"))
        self.assert_(result, True)

    def test_http_8(self):
        result = validate(print_in_yaml(data["http"][7], "HTTP"))
        self.assert_(result, True)

    def test_http_9(self):
        result = validate(print_in_yaml(data["http"][8], "HTTP"))
        self.assert_(result, True)

    def test_http_10(self):
        result = validate(print_in_yaml(data["http"][9], "HTTP"))
        self.assert_(result, True)

    def test_http_11(self):
        result = validate(print_in_yaml(data["http"][10], "HTTP"))
        self.assert_(result, True)

    def test_http_12(self):
        result = validate(print_in_yaml(data["http"][11], "HTTP"))
        self.assert_(result, True)

    def test_http_13(self):
        result = validate(print_in_yaml(data["http"][12], "HTTP"))
        self.assert_(result, True)

    def test_http_14(self):
        result = validate(print_in_yaml(data["http"][13], "HTTP"))
        self.assert_(result, True)

    def test_http_15(self):
        result = validate(print_in_yaml(data["http"][14], "HTTP"))
        self.assert_(result, True)

    def test_http_16(self):
        result = validate(print_in_yaml(data["http"][15], "HTTP"))
        self.assert_(result, True)


class TestHttps(unittest.TestCase):
    def test_https_1(self):
        result = validate(print_in_yaml(data["https"][0], "HTTPS"))
        self.assert_(result, True)

    def test_https_2(self):
        result = validate(print_in_yaml(data["https"][1], "HTTPS"))
        self.assert_(result, True)

    def test_https_3(self):
        result = validate(print_in_yaml(data["https"][2], "HTTPS"))
        self.assert_(result, True)

    def test_https_4(self):
        result = validate(print_in_yaml(data["https"][3], "HTTPS"))
        self.assert_(result, True)

    def test_https_5(self):
        result = validate(print_in_yaml(data["https"][4], "HTTPS"))
        self.assert_(result, True)

    def test_https_6(self):
        result = validate(print_in_yaml(data["https"][5], "HTTPS"))
        self.assert_(result, True)


class TestTelnet(unittest.TestCase):
    def test_telnet_1(self):
        result = validate(print_in_yaml(data["telnet"][0], "TELNET"))
        self.assert_(result, True)

    def test_telnet_2(self):
        result = validate(print_in_yaml(data["telnet"][1], "TELNET"))
        self.assert_(result, True)

    def test_telnet_3(self):
        result = validate(print_in_yaml(data["telnet"][2], "TELNET"))
        self.assert_(result, True)

    def test_telnet_4(self):
        result = validate(print_in_yaml(data["telnet"][3], "TELNET"))
        self.assert_(result, True)

    def test_telnet_5(self):
        result = validate(print_in_yaml(data["telnet"][4], "TELNET"))
        self.assert_(result, True)


class TestSSH(unittest.TestCase):
    def test_ssh_1(self):
        result = validate(print_in_yaml(data["ssh"][0], "SSH"))
        self.assert_(result, True)

    def test_ssh_2(self):
        result = validate(print_in_yaml(data["ssh"][1], "SSH"))
        self.assert_(result, True)


class TestFTPControl(unittest.TestCase):
    def test_FTP_C_1(self):
        result = validate(print_in_yaml(data["ftp-control"][0], "FTP-CONTROL"))
        self.assert_(result, True)

    def test_FTP_C_2(self):
        result = validate(print_in_yaml(data["ftp-control"][1], "FTP-CONTROL"))
        self.assert_(result, True)

    def test_FTP_C_3(self):
        result = validate(print_in_yaml(data["ftp-control"][2], "FTP-CONTROL"))
        self.assert_(result, True)

    def test_FTP_C_4(self):
        result = validate(print_in_yaml(data["ftp-control"][3], "FTP-CONTROL"))
        self.assert_(result, True)

    def test_FTP_C_5(self):
        result = validate(print_in_yaml(data["ftp-control"][4], "FTP-CONTROL"))
        self.assert_(result, True)

    def test_FTP_C_6(self):
        result = validate(print_in_yaml(data["ftp-control"][5], "FTP-CONTROL"))
        self.assert_(result, True)

    def test_FTP_C_7(self):
        result = validate(print_in_yaml(data["ftp-control"][6], "FTP-CONTROL"))
        self.assert_(result, True)

    def test_FTP_C_8(self):
        result = validate(print_in_yaml(data["ftp-control"][7], "FTP-CONTROL"))
        self.assert_(result, True)


class TestFTPData(unittest.TestCase):
    def test_FTP_D_1(self):
        result = validate(print_in_yaml(data["ftp-data"][0], "FTP-DATA"))
        self.assert_(result, True)

    def test_FTP_D_2(self):
        result = validate(print_in_yaml(data["ftp-data"][1], "FTP-DATA"))
        self.assert_(result, True)

    def test_FTP_D_3(self):
        result = validate(print_in_yaml(data["ftp-data"][2], "FTP-DATA"))
        self.assert_(result, True)

    def test_FTP_D_4(self):
        result = validate(print_in_yaml(data["ftp-data"][3], "FTP-DATA"))
        self.assert_(result, True)

    def test_FTP_D_5(self):
        result = validate(print_in_yaml(data["ftp-data"][4], "FTP-DATA"))
        self.assert_(result, True)

    def test_FTP_D_6(self):
        result = validate(print_in_yaml(data["ftp-data"][5], "FTP-DATA"))
        self.assert_(result, True)

    def test_FTP_D_7(self):
        result = validate(print_in_yaml(data["ftp-data"][6], "FTP-DATA"))
        self.assert_(result, True)

    def test_FTP_D_8(self):
        result = validate(print_in_yaml(data["ftp-data"][7], "FTP-DATA"))
        self.assert_(result, True)


class TestTFTPFilter(unittest.TestCase):
    def test_TFTP_1(self):
        result = validate(print_in_yaml(data["tftp"][0], "TFTP"))
        self.assert_(result, True)

    def test_TFTP_2(self):
        result = validate(print_in_yaml(data["tftp"][1], "TFTP"))
        self.assert_(result, True)

    def test_TFTP_3(self):
        result = validate(print_in_yaml(data["tftp"][2], "TFTP"))
        self.assert_(result, True)


class TestICMPFilter(unittest.TestCase):
    def test_ICMP_1(self):
        result = validate(print_in_yaml(data["icmp"][0], "ICMP"))
        self.assert_(result, True)

    def test_ICMP_2(self):
        result = validate(print_in_yaml(data["icmp"][1], "ICMP"))
        self.assert_(result, True)

    def test_ICMP_3(self):
        result = validate(print_in_yaml(data["icmp"][2], "ICMP"))
        self.assert_(result, True)

    def test_ICMP_4(self):
        result = validate(print_in_yaml(data["icmp"][3], "ICMP"))
        self.assert_(result, True)

    def test_ICMP_5(self):
        result = validate(print_in_yaml(data["icmp"][4], "ICMP"))
        self.assert_(result, True)

    def test_ICMP_6(self):
        result = validate(print_in_yaml(data["icmp"][5], "ICMP"))
        self.assert_(result, True)


class TestARPFilter(unittest.TestCase):
    def test_ARP_1(self):
        result = validate(print_in_yaml(data["arp"][0], "ARP"))
        self.assert_(result, True)

    def test_ARP_2(self):
        result = validate(print_in_yaml(data["arp"][1], "ARP"))
        self.assert_(result, True)

    def test_ARP_3(self):
        result = validate(print_in_yaml(data["arp"][2], "ARP"))
        self.assert_(result, True)

    def test_ARP_4(self):
        result = validate(print_in_yaml(data["arp"][3], "ARP"))
        self.assert_(result, True)

    def test_ARP_5(self):
        result = validate(print_in_yaml(data["arp"][4], "ARP"))
        self.assert_(result, True)

    def test_ARP_6(self):
        result = validate(print_in_yaml(data["arp"][5], "ARP"))
        self.assert_(result, True)

    def test_ARP_7(self):
        result = validate(print_in_yaml(data["arp"][6], "ARP"))
        self.assert_(result, True)

    def test_ARP_8(self):
        result = validate(print_in_yaml(data["arp"][7], "ARP"))
        self.assert_(result, True)

    def test_ARP_9(self):
        result = validate(print_in_yaml(data["arp"][8], "ARP"))
        self.assert_(result, True)

    def test_ARP_10(self):
        result = validate(print_in_yaml(data["arp"][9], "ARP"))
        self.assert_(result, True)

    def test_ARP_11(self):
        result = validate(print_in_yaml(data["arp"][10], "ARP"))
        self.assert_(result, True)

    def test_ARP_12(self):
        result = validate(print_in_yaml(data["arp"][11], "ARP"))
        self.assert_(result, True)

    def test_ARP_13(self):
        result = validate(print_in_yaml(data["arp"][12], "ARP"))
        self.assert_(result, True)

    def test_ARP_14(self):
        result = validate(print_in_yaml(data["arp"][13], "ARP"))
        self.assert_(result, True)

    def test_ARP_15(self):
        result = validate(print_in_yaml(data["arp"][14], "ARP"))
        self.assert_(result, True)

    def test_ARP_16(self):
        result = validate(print_in_yaml(data["arp"][15], "ARP"))
        self.assert_(result, True)

    def test_ARP_17(self):
        result = validate(print_in_yaml(data["arp"][16], "ARP"))
        self.assert_(result, True)

    def test_ARP_18(self):
        result = validate(print_in_yaml(data["arp"][17], "ARP"))
        self.assert_(result, True)

    def test_ARP_19(self):
        result = validate(print_in_yaml(data["arp"][18], "ARP"))
        self.assert_(result, True)
