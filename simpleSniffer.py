from scapy.all import *
pc=input("Do you want to choose a tcp port yes(Y)or no(N)\n") 
num=input("How many packets do you want to capture \n") 

if(pc=="Y"):
    port= input("what tcp port you want to sniff \n")
    print("Capturing packets, press crtl+C to exit")
    packets= sniff(filter="tcp port "+port,count=int(num))
else:
    packets= sniff(count=int(num))
    print("Capturing packets, press crtl+C to exit")
print("\n Packet Summary")
for pkt in packets:
    if IP in pkt:
       if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            print(pkt[IP].src+ ":TCP "+ str(src_port) + " > "+pkt[IP].dst + ":TCP "+str(dst_port))
       elif UDP in pkt:
           src_port = pkt[UDP].sport
           dst_port = pkt[UDP].dport
           print(pkt[IP].src+ ":UDP "+ str(src_port) + " > "+pkt[IP].dst +":UDP "+ str(dst_port))