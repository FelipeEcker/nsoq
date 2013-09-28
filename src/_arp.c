/*......,,,,,,,.............................................................
*
* @@NAME:     Module ARP
* @@VERSION:  1.0.2
* @@DESC:     ARP source file (this file is part of MpTcp tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     20/11/2012 04:30:00
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2013.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/

#include "../include/core.h"

struct __data _data;   /* Sender bulk */

struct __ethdr {
   ethaddr macdst;     /* 6 bytes [00-05]  */
   ethaddr macsrc;     /* 6 bytes [06-11]  */
   uint16 proto;       /* 2 bytes [12-13]  */
   uint16 unused0;     /* 2 bytes [14-15]  */
   uint16 unused1;     /* 2 bytes [16-17]  */
   uint16 unused2;     /* 2 bytes [18-19]  */
   uint16 type;        /* 2 bytes [20-21]  */
   ethaddr msrc;       /* 6 bytes [22-27]  */
   uint32 ipsrc;       /* 4 bytes [28-31]  */
   ethaddr mdst;       /* 6 bytes [32-37]  */
   uint32 ipdst;       /* 4 bytes [38-41]  */

} __packed__;          /* Packing 42 bytes */


#if defined(__LINUX_SYSTEM__)
inline static struct sockaddr_ll __lookup_ether( const char *eth ) {

   auto struct ifreq ifreq;
   static struct sockaddr_ll sll;

   strncpy(ifreq.ifr_ifrn.ifrn_name, eth, IFNAMSIZ);
   signed int __dummy = socket(AF_INET, SOCK_DGRAM, 0);

   if (ioctl(__dummy, SIOCGIFINDEX, &ifreq) < 0) {
      log("ERROR on fetching interface.\nTry use -i <interface>.\n");
      close(__dummy);
      kill(getpid(), SIGALRM);
   }

   close(__dummy);
   sll.sll_family = AF_PACKET;
   sll.sll_ifindex = ifreq.ifr_ifru.ifru_ivalue;

   return sll;
}
#endif


#if defined(__BSD_SYSTEM__)
static void __bsd_listen (  u_char *args,
                            const struct pcap_pkthdr *hdr,
                            const u_char *recvbuff )
{
   struct __ethdr *ether = (struct __ethdr *) recvbuff;
   auto char address_src[INET_ADDRSTRLEN], address_dst[INET_ADDRSTRLEN];

   __sysdate();
   inet_ntop(AF_INET, &(ether->ipsrc), address_src, INET_ADDRSTRLEN);
   inet_ntop(AF_INET, &(ether->ipdst), address_dst, INET_ADDRSTRLEN);

   if ( htons(ether->proto) == (uint16) ETH_ARP ) {

      if ( htons(ether->type) == (uint16) ETH_ARPREQ ) {
         show("(%02d:%02d:%02d) Received ARP REQUEST from [%s - %s] asking who is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec, address_src,
         eth_ntoa(&ether->macsrc), address_dst);

      } else if ( htons(ether->type) == (uint16) ETH_ARPREPLY ) {
         show("(%02d:%02d:%02d) Received ARP REPLY packet from [%s] saying it is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec, address_src,
         eth_ntoa(&ether->macsrc));

      } else {
         show("(%02d:%02d:%02d) Received an unknown ARP packet type.\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec);
      }

   } else if ( htons(ether->proto) == (uint16) ETH_RARP ) {

      if ( htons(ether->type) == (uint16) ETH_RARPREQ ) {
         show("(%02d:%02d:%02d) Received RARP REQUEST from [%s - %s] asking who is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec, address_src,
         eth_ntoa(&ether->macsrc), eth_ntoa(&ether->macdst));

      } else if ( htons(ether->type) == (uint16) ETH_ARPREPLY ) {
         show("(%02d:%02d:%02d) Received RARP REPLY from [%s] saying your IP is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec,
         eth_ntoa(&ether->macsrc), address_src);

      } else {
         show("(%02d:%02d:%02d) Received an unknown RARP packet type.\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec);
      }

   } else goto __DOWN;

    if (pkt->packetDisplay) __show_packet(recvbuff, pkt->buffsize + 42);
   __DOWN:
   pass;
}
#endif


inline static void __doListen() {

   show("Listening for ARP/RARP data [Capturing size %d bytes]:\n",
   (uint32) pkt->buffsize + 42);

#if defined(__BSD_SYSTEM__)
   auto char err[PCAP_ERRBUF_SIZE];

   if ( !(__session = pcap_open_live(pkt->interface,
   pkt->buffsize + 42, true, 1, err)) ) {
      log("Couldn't open device %s: %s\n", pkt->interface, err);
      kill(getpid(), SIGALRM);
      goto __FINISHING;
   }

   pcap_loop(__session, -1, __bsd_listen, NULL);

#else
   register uint32 sock;
   /* PF RAW socket*/
   if ( !( sock = __socketPool(false, __ARP_MODE__, false)) ) return;

   uchar recvbuff[pkt->buffsize + 42];

   struct __ethdr *ether = (struct __ethdr *) recvbuff;
   struct sockaddr_ll __nop__;
   auto char address_src[INET_ADDRSTRLEN], address_dst[INET_ADDRSTRLEN];
   auto socklen_t size = sizeof(recvbuff); 
   auto socklen_t size_ll = sizeof(struct sockaddr_ll);

   __STARTING:
   memset(recvbuff, 0, size);
   if ( hardfalse(recvfrom(sock, recvbuff, size, 0, \
   (struct sockaddr *) &__nop__, &size_ll) < 0) ) {
      log("ERROR on received data.\n\n");
      kill(getpid(), SIGALRM);
      goto __FINISHING;
   }

   __sysdate();
   inet_ntop(AF_INET, &(ether->ipsrc), address_src, INET_ADDRSTRLEN);
   inet_ntop(AF_INET, &(ether->ipdst), address_dst, INET_ADDRSTRLEN);

   if ( htons(ether->proto) == (uint16) ETH_ARP ) {

      if ( htons(ether->type) == (uint16) ETH_ARPREQ ) {
         show("(%02d:%02d:%02d) Received ARP REQUEST from [%s - %s] asking who is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec, address_src,
         eth_ntoa(&ether->macsrc), address_dst);

      } else if ( htons(ether->type) == (uint16) ETH_ARPREPLY ) {
         show("(%02d:%02d:%02d) Received ARP REPLY packet from [%s] saying it is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec, address_src,
         eth_ntoa(&ether->macsrc));

      } else {
         show("(%02d:%02d:%02d) Received an unknown ARP packet type.\n", 
         _t->tm_hour, _t->tm_min, _t->tm_sec);
      }

   } else if ( htons(ether->proto) == (uint16) ETH_RARP ) {

      if ( htons(ether->type) == (uint16) ETH_RARPREQ ) {
         show("(%02d:%02d:%02d) Received RARP REQUEST from [%s - %s] asking who is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec, address_src, 
         eth_ntoa(&ether->macsrc), eth_ntoa(&ether->macdst));

      } else if ( htons(ether->type) == (uint16) ETH_ARPREPLY ) {
         show("(%02d:%02d:%02d) Received RARP REPLY from [%s] saying your IP is [%s]\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec,
         eth_ntoa(&ether->macsrc), address_src);

      } else {
         show("(%02d:%02d:%02d) Received an unknown RARP packet type.\n",
         _t->tm_hour, _t->tm_min, _t->tm_sec);
      }

   } else goto __STARTING;

   if (pkt->packetDisplay) __show_packet(recvbuff, sizeof(recvbuff));
   goto __STARTING;

#endif

   __FINISHING:
   pass;
}


#if !defined(WEAK_GCC)
__hot__ inline static void __packing
#else
inline static void __packing
#endif
                        ( uchar *__buffer,
                          const uint32 __source,
                          const uint32 __target,
                          const char *macsrc,
                          const char *macdst,
                          const uint16 arpType, 
                          const uint16 mode )
{

   struct __ethdr *__eth = (struct __ethdr *) __buffer;
   __cache(__eth);

   eth_aton_r(macsrc, &__eth->macsrc);
   eth_aton_r(macdst, &__eth->macdst);
   __eth->proto   = htons(arpType);
   __eth->unused0   = (uint16) htons(0x0001);
   __eth->unused1   = (uint16) htons(0x0800);
   __eth->unused2   = (uint16) htons(0x0604);

   /* 0x0001=ARP_REQUEST / 0x0002=ARP_REPLY / 
      0x0003=RARP_REQUEST / 0x0004=RARP_REPLY 
   */
   __eth->type      = htons(mode);
   __eth->ipsrc     = __source;
   __eth->ipdst     = __target;
   __eth->msrc      = __eth->macsrc;
   __eth->mdst      = __eth->macdst;
}


#if defined(__BSD_SYSTEM__)
volatile uint32 counter = 0;
static void __arping_listen ( uchar *args,
                     const struct pcap_pkthdr *hdr,
                     const u_char *recvbuff)
{

   struct __ethdr *ether = (struct __ethdr *) recvbuff;

   if (_data.target->sin_addr.s_addr == ether->ipsrc) {
      show("(%d) Received reply packet from host %s [%s]\n",
      counter++, pkt->dst, eth_ntoa(&ether->macsrc));

      if (pkt->packetDisplay) __show_packet(recvbuff, (pkt->buffsize + 42));
      pcap_breakloop(__session);
   }
}
#endif


#if !defined(WEAK_GCC)
__hot__ inline static void __arping() {
#else
inline static void __arping() {
#endif

#if defined(__LINUX_SYSTEM__)
   auto uint32 sock;

   /* PF RAW socket*/
   if ( !( sock = __socketPool(false, __ARP_MODE__, false)) ) return;

   uchar recvbuff[pkt->buffsize + 42];
   socklen_t size = sizeof(recvbuff);

   struct sockaddr_ll __nop__;
   socklen_t size_ll = sizeof(struct sockaddr_ll);
   struct sockaddr_ll addr_ll = __lookup_ether(pkt->interface);

   struct __ethdr *__eth = (struct __ethdr *) recvbuff;
#endif

   snprintf(pkt->macsrc, ETH_LEN, __fetchMac(pkt->interface));
   snprintf(pkt->macdst, ETH_LEN, "FF:FF:FF:FF:FF:FF");

   uchar cbuffer[pkt->buffsize + 42] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));
   auto uint32 size_b = (uint32) sizeof(cbuffer);

   /* ARP REQUEST packet */
   __packing(cbuffer, _data.source->sin_addr.s_addr, 
   _data.target->sin_addr.s_addr, pkt->macsrc, pkt->macdst, 
   ETH_ARP, ETH_ARPREQ);

   __cache(&cbuffer);
   __cache(&size_b);

   register uint32 count = pkt->counter;
   show("Arping host [%s]:\n\n", pkt->dst);

#if defined(__BSD_SYSTEM__)
   signal(SIGCHLD, SIG_IGN);
   auto char err[PCAP_ERRBUF_SIZE];

   if ( !( __session = pcap_open_live(pkt->interface, 
   size_b, true, 1, err)) ) {
      log("Couldn't open device %s: %s\n", pkt->interface, err);
      kill(getpid(), SIGALRM);
      goto __STOPING;
   }

   __PING:
   if ( write(pkt->bpf, cbuffer, size_b) < 0) {
      log("ERROR on sent data.\n\n");
      kill(getpid(), SIGALRM);
      goto __STOPING;
   }

   pcap_loop(__session, -1, __arping_listen, NULL);

#else
   register uint32 counter = 0;

   __PING:
   if ( hardfalse(sendto(sock, cbuffer, size_b, 0, 
      (struct sockaddr *) &addr_ll, sizeof(struct sockaddr_ll)) < 0) ) {
      log("ERROR on sent data.\n\n");
      kill(getpid(), SIGALRM);
      goto __STOPING;
   }

   do {
      if ( hardfalse(recvfrom(sock, recvbuff, size, 0, 
         (struct sockaddr *) &__nop__, &size_ll) < 0 ) ) {
         log("ERROR on sent data.\n\n");
         kill(getpid(), SIGALRM);
         goto __STOPING;
      }

   } while ( _data.target->sin_addr.s_addr != __eth->ipsrc);

   show("(%d) Received reply packet from host %s [%s]\n", 
   counter++, pkt->dst, eth_ntoa(&__eth->macsrc));

   if (pkt->packetDisplay) __show_packet(recvbuff, sizeof(recvbuff));

#endif
   sleep(1);
   if (!(--count)) goto __STOPING;
   goto __PING;

   __STOPING:
   pass;
}


#if !defined(WEAK_GCC)
__hot__ inline static void __macflood() {
#else
inline static void __macflood() {
#endif

#if defined(__LINUX_SYSTEM__)
   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* PF RAW socket*/
   if ( !( sock = __socketPool(false, __ARP_MODE__, false)) ) return;
   pthread_mutex_unlock(&__mutex);

   struct sockaddr_ll addr_ll = __lookup_ether(pkt->interface);
   socklen_t size_ll = sizeof(struct sockaddr_ll);
#endif

   bool isConted = false;
   register uint32 count = pkt->counter;
   register uint64 cnt = 0;

   uchar cbuffer[pkt->buffsize + 42] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));

   do {
      show("[BURST] Mac flooding with %u packets...\n", (uint32) pkt->macflood);
      for (; cnt < pkt->macflood; cnt++) {

         inet_pton(AF_INET, __randomIp(), &_data.source->sin_addr.s_addr);
         inet_pton(AF_INET, __randomIp(), &_data.target->sin_addr.s_addr);

         /* ARP REPLY packet */
         __packing(cbuffer, _data.source->sin_addr.s_addr,
         _data.target->sin_addr.s_addr, __randomMac(), __randomMac(), 
         ETH_ARP, ETH_ARPREPLY);

#if defined(__BSD_SYSTEM__)
         write(pkt->bpf, cbuffer, (uint32) sizeof(cbuffer));
#else
         sendto(sock, cbuffer, (uint32) sizeof(cbuffer), 0,
         (struct sockaddr *) &addr_ll, size_ll);   
#endif
      }

      if (pkt->continuous) sleep(1);
      else if (pkt->flood) usleep(pkt->flood*100);
      else if (pkt->counter) {
         isConted = true;
         usleep(50000);
      }
      if (!(--count)) break;
   } while (pkt->continuous || pkt->flood || isConted);
}


#if !defined(WEAK_GCC)
__hot__ inline static void __arpcannon() {
#else
inline static void __arpcannon() {
#endif

   struct in_addr __src = _data.source->sin_addr;
   struct in_addr __dst = _data.target->sin_addr;

   if ( hardfalse(ntohl(__dst.s_addr) < ntohl(__src.s_addr)) ) {
      log("ERROR: Invalid range IP adrress.");
      kill(getpid(), SIGALRM);
      return;
   }

   struct in_addr __magick;
   inet_pton(AF_INET, pkt->magickIp, &__magick);

#if defined(__LINUX_SYSTEM__)
   register uint32 sock;
   pthread_mutex_lock(&__mutex);
   /* PF RAW socket */
   if ( !( sock = __socketPool(false, __ARP_MODE__, false)) ) return;
   pthread_mutex_unlock(&__mutex);

   struct sockaddr_ll addr_ll = __lookup_ether(pkt->interface);
   socklen_t size_ll = sizeof(struct sockaddr_ll);
#endif

   snprintf(pkt->macdst, ETH_LEN, "FF:FF:FF:FF:FF:FF");
   show("[BURST] Sending ARP CANNON to %u hosts (Range: %s--%s)...\n",
   (ntohl(__dst.s_addr) - ntohl(__src.s_addr)) + 1, pkt->src, pkt->dst);

   uchar cbuffer[pkt->buffsize + 42] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));

   register uint32 magick = ntohl(__magick.s_addr);
   register uint32 src = ntohl(__src.s_addr);
   register uint32 dst = ntohl(__dst.s_addr);
   register uint32 it = 0;
   register uchar *buffer = cbuffer;
   register uint8 size = (uint32) sizeof(cbuffer);
   register char *macdst = pkt->macdst;

#if defined(__LINUX_SYSTEM__)
   register struct sockaddr_ll *addr_ll_r = &addr_ll;
#endif

   __SEND:
   for (it = src; it <= dst; it++) {
      if (it == magick) continue;

      /* ARP REPLY packet */
      __packing(buffer, htonl(it), 0x00000000, __randomMac(),
      macdst, ETH_ARP, ETH_ARPREPLY);

#if defined(__BSD_SYSTEM__)
      write(pkt->bpf, buffer, size);
#else
      sendto(sock, buffer, size, 0, (struct sockaddr *)
      addr_ll_r, size_ll);
#endif
   }

   goto __SEND;
}


#if !defined(WEAK_GCC)
__hot__ inline static void __send() {
#else
inline static void __send() {
#endif

#if defined(__LINUX_SYSTEM__)
   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* PF RAW socket*/
   if ( !( sock = __socketPool(false, __ARP_MODE__, false)) ) return;
   pthread_mutex_unlock(&__mutex);

   struct sockaddr_ll addr_ll = __lookup_ether(pkt->interface);
   socklen_t size_ll = sizeof(struct sockaddr_ll);
#endif

   bool type, isConted = false;
   uint16 mode;
   uint32 count = pkt->counter;
   uint32 cnt= 0;
   const char *msg;

   /* ARP Type */
   if (!pkt->arpType) {
      msg = "ARP";
      type = ETH_ARP;
      mode = (pkt->arpSender) ? ETH_ARPREQ : ETH_ARPREPLY;
   /* RARP Type */
   } else {
      msg = "RARP";
      type = ETH_RARP;
      mode = (pkt->arpSender) ? ETH_RARPREQ : ETH_RARPREPLY;
   }

   if ( !(*pkt->macsrc) ) 
      snprintf(pkt->macsrc, ETH_LEN, __fetchMac(pkt->interface));

   uchar cbuffer[pkt->buffsize + 42] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));

   __packing(cbuffer, _data.source->sin_addr.s_addr, 
   _data.target->sin_addr.s_addr, pkt->macsrc, pkt->macdst, type, mode);

   __cache(pkt->macdst);
   __cache(cbuffer);

   do {
      show("(%d) Sending %s packet to destination MAC address [%s]\n",
      cnt++, msg, pkt->macdst);

#if defined(__BSD_SYSTEM__)
      write(pkt->bpf, cbuffer, (uint32) sizeof(cbuffer));
#else
      sendto(sock, cbuffer, (uint32) sizeof(cbuffer), 0, 
      (struct sockaddr *) &addr_ll, size_ll);
#endif

      if (pkt->continuous) sleep(1);
      else if (pkt->flood) usleep(pkt->flood*100);
      else if (pkt->counter) {
         isConted = true;
         usleep(50000);
      }
      if (!(--count)) break;
   } while (pkt->continuous || pkt->flood || isConted);
}


#if !defined(WEAK_GCC)
__hot__ inline static void __burst() {
#else
inline static void __burst() {
#endif

#if defined(__LINUX_SYSTEM__)
   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* PF RAW socket */
   if ( !( sock = __socketPool(false, __ARP_MODE__, false)) ) return;
   pthread_mutex_unlock(&__mutex);

   struct sockaddr_ll addr_ll = __lookup_ether(pkt->interface);
   socklen_t size_ll = sizeof(struct sockaddr_ll);
#endif

   uint16 mode;
   bool type;
   const char *msg;

   /* ARP Type */
   if (!pkt->arpType) {
      msg = "ARP";
      type = ETH_ARP;
      mode = (pkt->arpSender) ? ETH_ARPREQ : ETH_ARPREPLY;
   /* RARP Type */
   } else {
      msg = "RARP";
      type = ETH_RARP;
      mode = (pkt->arpSender) ? ETH_RARPREQ : ETH_RARPREPLY;
   }

   if ( !(*pkt->macsrc) )
      snprintf(pkt->macsrc, ETH_LEN, __fetchMac(pkt->interface));

   uchar cbuffer[pkt->buffsize + 42] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));

   __packing(cbuffer, _data.source->sin_addr.s_addr, 
   _data.target->sin_addr.s_addr, pkt->macsrc, pkt->macdst, type, mode);

   register uchar *buffer = cbuffer;
   register uint8 size = (uint32) sizeof(cbuffer);
#if defined(__LINUX_SYSTEM__)
   register struct sockaddr_ll *addr_ll_r = &addr_ll;
   register uint8 size_r = size_ll;
#endif

   show("[BURST] Sending %s packet to destination MAC [%s]...\n",
   msg, pkt->macdst);

   __SEND:
#if defined(__BSD_SYSTEM__)
   write(pkt->bpf, buffer, size);
#else
   sendto(sock, buffer, size, 0, (struct sockaddr *) addr_ll_r, size_r);
#endif

   goto __SEND;
}


bool arp( const char **pull __unused__ ) {

   signal(SIGINT, __sigcatch);
   signal(SIGALRM, __sigcatch);

   _data.source = (struct sockaddr_in *) addressbuff;
   _data.target = (struct sockaddr_in *) addressbuff + sizeof(struct sockaddr_in);

   if (!__lookup(_data.source, pkt->src, pkt->srcport, true)) return false;

#if defined(__BSD_SYSTEM__)
   if ( !(pkt->bpf = __checkBPF(pkt->interface)) ) {
      log("Error on grab bpf. No such device.\n\n");
      return false;
   }
#endif

   if (pkt->listenMode & LISTEN_ARP) {
      __doListen();
      goto __FINISH_ARP;
   }   

   if (!__lookup(_data.target, pkt->dst, pkt->port, false)) return false;

   const void *func;
   if (pkt->arpMode & ARP_PING) {
      __arping();
      goto __FINISH_ARP;
   }
   else if (pkt->arpMode & ARP_FLOOD) func = &__macflood;
   else if (pkt->arpMode & ARP_CANNON) func = &__arpcannon;
   else if (pkt->superFlood) func = &__burst;
   else func = &__send;

   if ( !__threadPool(pkt->numThreads, func, NULL) ) return false;
   pthread_exit(0);

   __FINISH_ARP:
   return true;
}

