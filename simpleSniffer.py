from scapy.all import *
import pandas as pd
from datetime import datetime
pc=input("Do you want to choose a tcp port yes(Y)or no(N)\n") 
num=input("How many packets do you want to capture \n") 
table=pd.DataFrame(columns=['Time','src','dst'])
pd.set_option('display.max_rows', None) ## allows all rows of the table to be printed to output

#center aligns the column headers
# Center-align the headers and data
table.style.set_table_styles({
    '': {'text-align': 'center'},  # Center the data
    'th': {'text-align': 'center'}  # Center the headers
})

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
            time=datetime.utcfromtimestamp(pkt[IP].time).strftime('%Y-%m-%d %H:%M:%S')
            table.loc[len(table)]=[time,pkt[IP].src+ ":TCP ",pkt[IP].dst + ":TCP "+str(dst_port)]
            
       elif UDP in pkt:
           src_port = pkt[UDP].sport
           dst_port = pkt[UDP].dport
           time=datetime.utcfromtimestamp(pkt[IP].time).strftime('%Y-%m-%d %H:%M:%S')
           table.loc[len(table)]=[time,pkt[IP].src+ ":UDP ",pkt[IP].dst + ":UDP "+str(dst_port)]
          
print(table)