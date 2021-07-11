# Packet Sniffer
A simple packer sniffer written in python. Currently, it only supports TCP, UDP and ICMP protocols.

It logs all frames/packets that are sent or received by your computer.

## How to use
Run `sudo ./sniffer.py [-flag]`
#### Flags
- `-t` for TCP only
- `-u` for UDP only
- `-i` for ICMP only

>Note: By default, it logs every 2s, but you can change it to whatever you want by changing `SLEEP_TIME` variable.
