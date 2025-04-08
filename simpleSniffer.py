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

print(packets.summary())
