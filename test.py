import dpkt

def calculate_cwnd(pcap_file):
    # Initialize variables
    connection = {}
    cwnd = 0

    # Open pcap file and parse packets
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data

            # Check for SYN, ACK, or FIN flags to start or end a connection
            if tcp.flags & dpkt.tcp.TH_SYN:
                connection[tcp.seq] = tcp
            elif tcp.flags & dpkt.tcp.TH_FIN:
                del connection[tcp.ack]
            elif tcp.flags & dpkt.tcp.TH_ACK:
                if tcp.ack in connection:
                    # Calculate congestion window size
                    cwnd = tcp.seq - connection[tcp.ack].ack
                    connection[tcp.ack] = tcp

    return cwnd

calculate_cwnd('assignment2pcap.pcap')