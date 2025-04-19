from scapy.all import *

def runLiveSniff():
    packets=[]
    count=0
    def packet_callback(pkt):
        nonlocal count
        packets.append(pkt)
        count+=1
        if ARP in pkt:
                print(f"[{count}][ARP] {pkt[ARP].psrc} -> {pkt[ARP].pdst}")
        elif IP in pkt:
            
            if ICMP in pkt:
                    print(f"[{count}][ICMP] {pkt[IP].src} -> {pkt[IP].dst} Type: {pkt[ICMP].type}")
            elif TCP in pkt:
                    print(f"[{count}][TCP] {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
            elif UDP in pkt:
                    print(f"[{count}][UDP] {pkt[IP].src}:{pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[UDP].dport}")
            if DNS in pkt and pkt[DNS].qd is not None:
                  print(f"[DNS] {pkt[IP].src} -> {pkt[IP].dst} : {pkt[DNS].qd.qname.decode()}")
    print("To Stop Sniffing Press Ctrl+C")
    sniff(prn=packet_callback, filter="ip or arp", store=False)
    print(f"{count} packets captured")
    if(packets):
        saveOrNot=input("Do you want to save the output to a pcap file Yes(Y) or No(N) \n")
        if(saveOrNot.strip().lower()=="y"):
            fName=input("What do you want to Name this File (Please input just file name with no extension)\n")
            wrpcap(f"pcaps/{fName}.pcap", packets)
            print("File Saved as pcaps/"+fName+".pcap")
    else:
        print("No packets were captured.")