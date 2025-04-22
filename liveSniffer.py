from scapy.all import *
from sharedFunctions import twoValueInput
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
                  
    
    filterOrNot=twoValueInput("Do you want to filter by a specific port yes(y) or no(n)\n"
                              ,"Please enter either y for yes or n for no",'y','n')
                  
  
    if(filterOrNot=='n'):
        print("To Stop Sniffing Press Ctrl+C")
        sniff(prn=packet_callback, store=False)
    else:
        tu=twoValueInput("Choose udp or tcp for port type\n","Please type tcp or udp","tcp","udp")
        portNum=input("Please enter the port number")
        print(f'Sniffing {tu} Port {portNum}.To Stop Sniffing Press Ctrl+C')
        sniff(prn=packet_callback,filter=f'{tu} port {portNum}',store=False)
    print(f"{count} packets captured")
    if(packets):
        saveOrNot=twoValueInput("Do you want to save the output to a pcap file Yes(y) or No(n) \n"
                                   ,"Please enter y for yes and n for no",'y','n')
        if(saveOrNot=="y"):
            fName=input("What do you want to Name this File (Please input just file name with no extension)\n")
            wrpcap(f"pcaps/{fName}.pcap", packets)
            print("File Saved as pcaps/"+fName+".pcap")
    else:
        print("No packets were captured.")