# Packet Sniffing

A simple but effective network packet sniffer built with **Python**, **Scapy**, and **Pandas**.  
This tool allows you to capture, filter, and summarize packets from your network, with optional port and protocol filtering and the ability to save captured data to a `.pcap` file.

---

## Features
- **Live Sniffing**: Capture packets in real time.
- **Batch Smiffing**: Capture a set number of packets in batches.
- **Protocol Filtering**: Capture only `TCP`, `UDP`, or all packets.
- **Port Filtering**: Target a specific port or let it sniff freely.
- **Custom Packet Limits**: Specify how many packets you want to capture.
- **Timeout Control**: Set how long the sniffer will run if the packet count isn’t met.
- **User-Friendly Summary**: Displays packet information in a clean Pandas DataFrame.
- **PCAP Export**: Save your captured packets for later analysis using tools like Wireshark.
- **CSV Export**: Save Summaries of batched packet captures to csv files.
- **Loop Mode**: Run multiple captures back-to-back without restarting the program.

---

## Requirements

- Python 3.x  
- Scapy (`pip install scapy`)  
- Pandas (`pip install pandas`)  

> **Note:** Administrator or root privileges are required for packet sniffing on most systems.

---

## Usage

Run the script with:

```bash
python main.py
