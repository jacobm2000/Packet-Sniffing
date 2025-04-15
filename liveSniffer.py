from scapy.all import *

def runLiveSniff():
    packets=[]
    def packet_callback(pkt):
        packets.append(pkt)
        if IP in pkt:
            if TCP in pkt:
                print(f"[TCP] {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
            elif UDP in pkt:
                print(f"[UDP] {pkt[IP].src}:{pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[UDP].dport}")
    
    print("To Stop Sniffing Press Ctrl+C")
    sniff(prn=packet_callback, filter="ip", store=False)
    if(packets):
        saveOrNot=input("Do you want to save the output to a pcap file Yes(Y) or No(N) \n")
        if(saveOrNot.strip().lower()=="y"):
            fName=input("What do you want to Name this File (Please input just file name with no extension)\n")
            wrpcap(fName+".pcap", packets)
            print("File Saved as "+fName+".pcap")
    else:
        print("No packets were captured.")