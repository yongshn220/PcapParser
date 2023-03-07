import dpkt
import socket

def main():
    pcapfile = 'assignment2pcap.pcap'

    flow = {}

    with open(pcapfile, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    if tcp.flags == dpkt.tcp.TH_SYN:
                        flow[tcp.sport] = getFlowStruct(tcp)
                        flow[tcp.sport]["ISQ"] = tcp.seq
                        flow[tcp.sport]["packets"].append(getPacketDataString(ip, "SYN", flow[tcp.sport]))
                        continue
                    if tcp.flags & dpkt.tcp.TH_FIN:
                        if tcp.sport not in flow: continue
                        flow[tcp.sport]["packets"].append(getPacketDataString(ip, "FIN", flow[tcp.sport]))
                        continue
                    if tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:
                        if tcp.dport not in flow: continue
                        flow[tcp.dport]["IACK"] = tcp.seq
                        setWinScale(tcp, flow[tcp.dport])
                        continue
                    if tcp.flags & dpkt.tcp.TH_ACK:
                        if tcp.sport not in flow: continue
                        if flow[tcp.sport]["num_of_packets"] >= 5: continue
                        flow[tcp.sport]["packets"].append(getPacketDataString(ip, "ACK", flow[tcp.sport]))
                        flow[tcp.sport]["num_of_packets"] += 1
                        continue

    i = 1
    for port in flow:
        print(f'-------- FLOW {i}---------')
        for packet in flow[port]["packets"]:
            print(packet)
        i += 1


def getFlowStruct(tcp):
    return {"packets": [], "num_of_packets": 0, "ISQ": 0, "IACK": 0, "WS": 1}


def setWinScale(tcp, flowItem):
    if dpkt.tcp.TCP_OPT_WSCALE in tcp.opts:
        parsed_opts = dpkt.tcp.parse_opts(tcp.opts)

        for opt_type, value in parsed_opts:
            if opt_type == dpkt.tcp.TCP_OPT_WSCALE:
                flowItem["WS"] = 2 ** int.from_bytes(value, "big")


def getPacketDataString(ip, type, flowItem):
    tcp = ip.data
    sip = socket.inet_ntoa(ip.src)
    sport = tcp.sport
    dip = socket.inet_ntoa(ip.dst)
    dport = tcp.dport
    return f'[{type}] -- source ip : {sip} | source port: {sport} | dest ip : {dip} | dest port : {dport}' \
           f' | SEQ: {tcp.seq - flowItem["ISQ"]}, ACK: {tcp.ack - flowItem["IACK"]}, windowSize: {tcp.win * flowItem["WS"]}'

main()