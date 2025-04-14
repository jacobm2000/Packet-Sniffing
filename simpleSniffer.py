from scapy.all import *
import pandas as pd
from datetime import datetime


done=False#keeps track of weather the user wants to continue the program or not
while(done==False):
    pc=input("Do you want to choose filter by tcp or udp yes(Y)or no(N)\n") 
    gettingPacketNum=True
    
    #this loop asks the user for the number of packets, and if it is not a integer value it will try again
    while(gettingPacketNum):
        num=input("How many packets do you want to capture \n")
        #if the value of the input is an integer than it is valid and the program can continue
        # if not an error message will display and the user will be propted for input again
        try:
            int(num)
            gettingPacketNum=False
        except:
            print("please input an integer value for the number of packets you want to capture")
            
    table=pd.DataFrame(columns=['Time','src','dst','flags','size(bytes)'])
    pd.set_option('display.max_rows', None) ## allows all rows of the table to be printed to output
    
    #center aligns the column headers
    # Center-align the headers and data
    table.style.set_table_styles({
        '': {'text-align': 'center'},  # Center the data
        'th': {'text-align': 'center'}  # Center the headers
    })
    
    if(pc.strip().lower()=="y"):
        selected=False## keeps track of wheather user properly selects tcp or udp
        while(selected==False):
            tu=input("Choose udp or tcp for port type\n")#figures out if the user wants tcp or udp
            if(str(tu.strip().lower())!="tcp" and str(tu.strip().lower())!="udp"):
              print("please choose either tcp or udp")
            else:
                selected=True
        portOrNot=input("Do you want to filter a specific port Yes(Y) or No(N)")
        if(portOrNot.strip().lower()=="y"): 
            port= input("what "+tu +" port you want to sniff \n")
            print("Capturing packets, press crtl+C to exit")
            packets= sniff(filter=tu+ " port "+port,count=int(num))
        else:
            print("Capturing packets, press crtl+C to exit")
            packets= sniff(filter=tu,count=int(num))
        
        
    else:
        print("Capturing packets, press crtl+C to exit")
        packets= sniff(count=int(num))
    print("\n Packet Summary")
    for pkt in packets:
        if IP in pkt:
           if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags=pkt[TCP].flags
                flag_str= flags.flagrepr()
                time=datetime.utcfromtimestamp(pkt[IP].time).strftime('%Y-%m-%d %H:%M:%S')
                table.loc[len(table)]=[time,pkt[IP].src+ ":TCP "+str(src_port),pkt[IP].dst + ":TCP "+str(dst_port),flag_str,len(pkt)]
                
           elif UDP in pkt:
               src_port = pkt[UDP].sport
               dst_port = pkt[UDP].dport
               time=datetime.utcfromtimestamp(pkt[IP].time).strftime('%Y-%m-%d %H:%M:%S')
               table.loc[len(table)]=[time,pkt[IP].src+ ":UDP "+str(src_port),pkt[IP].dst + ":UDP "+str(dst_port),"N/A",len(pkt)]
              
    print(table)
    
    # gets answer from user to see if they eant to save to pcap
    saveOrNot=input("do you want to save the output to a pcap file Yes(Y) or No(N) \n")
    if(saveOrNot.strip().lower()=="y"):
        fName=input("What do you want to Name this File (Please input just file name with no extension)\n")
        wrpcap(fName+".pcap", packets)
        print("File Saved as "+fName+".pcap")
    doneYet=input("do You want to do another capture Yes(Y) or NO(N)\n ")
    if(doneYet.lower()=="n"):
        done=True
        print("Program Terminated. Have a Great Day")