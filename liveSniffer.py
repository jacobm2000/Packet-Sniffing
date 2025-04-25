from scapy.all import *
from sharedFunctions import twoValueInput
from collections import Counter

def runLiveSniff():
    """
    Captures live network packets, optionally filters by protocol and port,
    and identifies the most frequent source and destination ports.
     """
    packets=[]
    count=0
    #Intializing counters for source and destination ports. The counters will be used to track the most common ports
    srcPorts=Counter()
    dstPorts=Counter()
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
                    srcPorts[pkt[TCP].sport]+=1
                    dstPorts[pkt[TCP].dport]+=1
                    print(f"[{count}][TCP] {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
            elif UDP in pkt:
                    srcPorts[pkt[UDP].sport]+=1
                    dstPorts[pkt[UDP].dport]+=1
                    print(f"[{count}][UDP] {pkt[IP].src}:{pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[UDP].dport}")
            # DNS packets may not always contain a 'qd' field; check is required to avoid exceptions
            if DNS in pkt and pkt[DNS].qd is not None:
                  print(f"[DNS] {pkt[IP].src} -> {pkt[IP].dst} : {pkt[DNS].qd.qname.decode()}")
                  
    #Checks if the user wants to filter packets by port
    filterOrNot=twoValueInput("Do you want to filter by a specific port yes(y) or no(n)\n"
                              ,"Please enter either y for yes or n for no",'y','n')
                  
  
    if(filterOrNot=='n'):
        print("To Stop Sniffing Press Ctrl+C")
        sniff(prn=packet_callback, store=False)
        #gets the three most common source and destination ports found while sniffing
        mostCommonSrc=srcPorts.most_common(3)
        mostCommonDst=dstPorts.most_common(3)
        
        # if mostCommonSrc has entrys then iterate through them and output to the user
        if (mostCommonSrc):
            print("\n Most common source ports")
            for i in range(len(mostCommonSrc)):
                print(f'#{i+1} Most frequent source port: {mostCommonSrc[i][0]} {mostCommonSrc[i][1]} times ')
        # if mostCommonDst has entrys then iterate through them and output to the user
        if (mostCommonDst):
            print("\n Most destination source ports")
            for i in range(len(mostCommonDst)):
                print(f'#{i+1} Most frequent destination port: {mostCommonDst[i][0]} {mostCommonDst[i][1]} times ')
    else:
        tu=twoValueInput("Choose udp or tcp for port type\n","Please type tcp or udp","tcp","udp")
        portNum=input("Please enter the port number\n")
        print(f'Sniffing {tu} Port {portNum}.To Stop Sniffing Press Ctrl+C')
        sniff(prn=packet_callback,filter=f'{tu} port {portNum}',store=False)
    
    if(packets):
        
        print(f"\n {count} packets captured")
        saveOrNot=twoValueInput("Do you want to save the output to a pcap file Yes(y) or No(n) \n"
                                   ,"Please enter y for yes and n for no",'y','n')
        if(saveOrNot=="y"):
            fName=input("What do you want to Name this File (Please input just file name with no extension)\n")
            wrpcap(f"pcaps/{fName}.pcap", packets)
            print("File Saved as pcaps/"+fName+".pcap")
    else:
        print("No packets were captured.")