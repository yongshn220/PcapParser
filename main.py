import dpkt
import socket
import datetime

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
                    if tcp.sport in flow:
                        flow[tcp.sport]["TP"] += len(tcp.data)
                    if tcp.flags == dpkt.tcp.TH_SYN:
                        flow[tcp.sport] = getFlowStruct()
                        flow[tcp.sport]["ISQ"] = tcp.seq  # Initial SEQ (To get the relative SEQ)
                        flow[tcp.sport]["dIACK"] = tcp.seq
                        flow[tcp.sport]["packets"].append(getPacketDataString(ip, "SYN", flow[tcp.sport]))
                        flow[tcp.sport]["ts0"] = ts
                        continue
                    # [FIN]
                    if tcp.flags & dpkt.tcp.TH_FIN:
                        if tcp.sport not in flow: continue
                        flow[tcp.sport]["packets"].append(getPacketDataString(ip, "FIN", flow[tcp.sport]))
                        continue
                    # [SYN ACK] Receiver -> Sender
                    if tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:
                        if tcp.dport not in flow: continue
                        flow[tcp.dport]["rtt"] = ts - flow[tcp.dport]["ts0"]
                        flow[tcp.dport]["l_ts"] = ts
                        flow[tcp.dport]["IACK"] = tcp.seq  # Initial ACK (To get the relative SEQ)
                        flow[tcp.dport]["last_ack"] = tcp.ack
                        setWinScale(tcp, flow[tcp.dport])
                        continue
                    if tcp.flags & dpkt.tcp.TH_ACK:
                        # Receiver -> Sender
                        if tcp.dport in flow:
                            # TimeStamp Calculation
                            # if the passed timestamp is greater than the 2*RTT, than it is considered as TIMEOUT
                            if ts - flow[tcp.dport]["l_ts"] > 2*flow[tcp.dport]["rtt"]:
                                flow[tcp.dport]["num_of_to"] += 1
                            # Congestion Window Size Calculation
                            if len(flow[tcp.dport]["cwnds"]) <= 2:
                                lseq, lack, isq, diack = flow[tcp.dport]["last_seq"], flow[tcp.dport]["last_ack"], flow[tcp.dport]["ISQ"], flow[tcp.dport]["dIACK"]
                                # Calculate the ack, seq differences between last received ACK and last sent SEQ.
                                flow[tcp.dport]["cwnds"].append((lseq - isq) - (lack - diack))
                            # Calculate the 3 Dup ACK
                            if flow[tcp.dport]["last_ack"] == tcp.ack:
                                flow[tcp.dport]["num_of_dup"] += 1
                                # if Dup Ack occurred 3 times, it is considered triple DUP ACK
                                if flow[tcp.dport]["num_of_dup"] == 3:
                                    flow[tcp.dport]["num_of_dup"] = 0
                                    flow[tcp.dport]["num_of_3dup"] += 1
                            flow[tcp.dport]["last_ack"] = tcp.ack
                            flow[tcp.dport]["l_ts"] = ts

                        # Sender -> Receiver
                        # Save the first two packets after SYNC
                        if tcp.sport in flow:
                            if flow[tcp.sport]["num_of_packets"] < 2:
                                flow[tcp.sport]["packets"].append(getPacketDataString(ip, "ACK", flow[tcp.sport]))
                                flow[tcp.sport]["num_of_packets"] += 1
                            flow[tcp.sport]["last_seq"] = tcp.seq

    i = 1
    for port in flow:
        print(f'-------- FLOW {i}---------')
        for packet in flow[port]["packets"]:
            print(packet)
        print("| congestion window sizes:", flow[port]["cwnds"])
        print("| triple dup ack count:", flow[port]["num_of_3dup"])
        print("| timeout count:", flow[port]["num_of_to"])
        i += 1



def getFlowStruct():
    return {"packets": [], "num_of_packets": 0, "last_ack": 0, "last_seq": 0, "cwnds": [], "ISQ": 0, "IACK": 0, "dIACK":0, "WS": 1, "TP": 0, "num_of_dup": 0, "num_of_3dup": 0, "l_ts": 0, "rtt":0, "num_of_to": 0}

# Calculate the Window Size = (Window Size * Window Scale)
def setWinScale(tcp, flowItem):
    if dpkt.tcp.TCP_OPT_WSCALE in tcp.opts:
        parsed_opts = dpkt.tcp.parse_opts(tcp.opts)

        for opt_type, value in parsed_opts:
            if opt_type == dpkt.tcp.TCP_OPT_WSCALE:
                flowItem["WS"] = 2 ** int.from_bytes(value, "big")


# ACK and SEQ is calculated by [Raw SEQ - Init SEQ] and [Raw ACK - init ACK]
def getPacketDataString(ip, type, flowItem):
    tcp = ip.data
    sip = socket.inet_ntoa(ip.src)
    sport = tcp.sport
    dip = socket.inet_ntoa(ip.dst)
    dport = tcp.dport
    return f'[{type}] -- source ip : {sip} | source port: {sport} | dest ip : {dip} | dest port : {dport}' \
           f' | SEQ: {tcp.seq - flowItem["ISQ"]}, ACK: {tcp.ack - flowItem["IACK"]}, SEQ(raw): {tcp.seq}, ACK(raw): {tcp.ack} , windowSize: {tcp.win * flowItem["WS"]}' \
           + (f' \n| Throughput: {flowItem["TP"]} bytes' if (type == "FIN") else '')

main()