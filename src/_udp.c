/*......,,,,,,,.............................................................
*
* @@NAME:     Module UDP
* @@VERSION:  1.0.2
* @@DESC:     UDP source file (this file is part of MpTcp tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     17/11/2012 11:50:00
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2013.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/

#include "../include/core.h"

static struct __data _data;         /* Sender bulk */

#if defined(__BSD_SYSTEM__)
static void __bsd_listen (  u_char *args,
                     const struct pcap_pkthdr *hdr,
                     const u_char *recvbuff )
{

   /* auto struct ether_header *h = (struct ether_header *) recvbuff; */
   auto struct ip *ip = (struct ip *) (recvbuff + SIZE_ETH);
   auto struct udphdr *udp = (struct udphdr *) (recvbuff + SIZE_IP + SIZE_ETH);

   __sysdate();
   auto char aux[20] __nocommon__, address[INET_ADDRSTRLEN] __nocommon__;

   if (ip->ip_p != IPPROTO_UDP) goto __BE_END;
   if ( pkt->port == ntohs(udp->uh_sport) ) goto __CATCHING;
   if ( ntohs(udp->uh_dport) != pkt->srcport ) goto __BE_END;

   __CATCHING:
   memset(aux, 0, sizeof(aux));
   inet_ntop(AF_INET, &(ip->ip_src), address, INET_ADDRSTRLEN);

   show("(%02d:%02d:%02d) Received UDP packet from host [%s:%d] with %d Bytes: TTL=%d\n", \
   _t->tm_hour, _t->tm_min, _t->tm_sec, address, ntohs(udp->uh_sport),
   ntohs(ip->ip_len), ip->ip_ttl);

   if (pkt->packetDisplay) __show_packet(&recvbuff[14], ntohs(ip->ip_len));

   __BE_END:
   pass;
}
#endif


inline static void __doListen() {

#if defined(__BSD_SYSTEM__)

   auto char *eth, err_buff[PCAP_ERRBUF_SIZE];

   if (pkt->port)
      show("Listening for UDP data on local port (%d) or remote port (%d) [Capturing size %d bytes]:\n",
      pkt->srcport, pkt->port, (uint32) pkt->buffsize + 512);
   else show("Listening for UDP data on local port (%d) [Capturing size %d bytes]:\n", 
      pkt->srcport, (uint32) pkt->buffsize + 512);

   if ( !(eth = pcap_lookupdev(err_buff)) ) {
      log("ERROR on grab system's interface. Exiting..\n\n");
      kill(getpid(), SIGALRM);
      goto __TAIL;
   }

   if ( !(__session = pcap_open_live(eth, pkt->buffsize + 512, true, 1, err_buff)) ) {
      log("Couldn't open device %s: Detail: %s\n", eth, err_buff);
      kill(getpid(), SIGALRM);
      goto __TAIL;
   }

   pcap_loop(__session, -1, __bsd_listen, NULL);

#else
   register signed int sock;
   /* UDP RAW socket*/
   if ( !( sock = __socketPool(false, __UDP_MODE__, false)) ) return;

   __set_hdrincl(sock);

   auto uchar recvbuff[pkt->buffsize + 512];
   register uint32 size = sizeof(recvbuff);

   auto struct sockaddr_in remote;
   unsigned _sizeof = sizeof(struct sockaddr_in);
   char address[INET_ADDRSTRLEN];

   struct iphdr *recvip = (struct iphdr *) recvbuff;
   struct udphdr *recvudp = (struct udphdr *) (recvbuff + SIZE_IP);

   if (pkt->port)
      show("Listening for UDP data on local port (%d) or remote port (%d) [Capturing size %d bytes]:\n",
      pkt->srcport, pkt->port, size);
   else show("Listening for UDP data on local port (%d) [Capturing size %d bytes]:\n", pkt->srcport, size);

   __LISTENING:
   memset(recvbuff, 0, size);
   if ( hardfalse(recvfrom(sock, recvbuff, size, 0, \
   (struct sockaddr *) &remote, &_sizeof) < 0) ) {
      log("ERROR on received data.\n\n");
      kill(getpid(), SIGALRM);
      goto __TAIL;
   }

   if (recvip->protocol != 0x11) goto __LISTENING;
   if ( (pkt->port) && (ntohs(recvudp->source) == pkt->port) )
      goto __CATCH_IN;
   if (ntohs(recvudp->dest) != pkt->srcport) goto __LISTENING;

   __CATCH_IN:
   __sysdate();
   inet_ntop(AF_INET, &(recvip->saddr), address, INET_ADDRSTRLEN);
   show("(%02d:%02d:%02d) Received UDP packet from host [%s:%d] with %d Bytes: TTL=%d\n", \
   _t->tm_hour, _t->tm_min, _t->tm_sec, address, ntohs(recvudp->source),
   ntohs(recvip->tot_len), recvip->ttl);

   if (pkt->packetDisplay) __show_packet(recvbuff, ntohs(recvip->tot_len));
   goto __LISTENING;

#endif
   __TAIL:
   pass;
}


inline static void __packing( uchar *__buffer,
                              const uint16 __size,
                              const struct sockaddr_in *__source,
                              const struct sockaddr_in *__target ) {

#if defined(__LINUX_SYSTEM__)
   struct iphdr *__ip = (struct iphdr *) __buffer;
#else
   struct ip *__ip = (struct ip *) __buffer;
#endif

   struct udphdr *__udp = (struct udphdr *) (__buffer + SIZE_IP);
   struct __auxhdr {
      uint32 saddr;
      uint32 daddr;
      uint8 useless;
      uint8 proto;
      uint16 udpsiz;
      struct udphdr udp;
      uchar data[__size - (SIZE_IP + SIZE_UDP)];

   } __packed__ udpaux;

#if defined(__LINUX_SYSTEM__)
   __ip->saddr    = __source->sin_addr.s_addr;
   __ip->daddr    = __target->sin_addr.s_addr;
   __ip->version  = 0x04;
   __ip->ihl      = 0x05;
   __ip->ttl      = pkt->ttl;
   __ip->id       = htons(rand() % 0xFFFF);
   __ip->protocol = IPPROTO_UDP;
   __ip->tot_len  = htons(__size); /* HeaderIP and headerUDP: 28 bytes */
   __ip->check    = __checksum((uint16 *) __ip, SIZE_IP);

   __udp->source  = __source->sin_port;
   __udp->dest    = __target->sin_port;
   __udp->len     = htons(__size - SIZE_IP);
   __udp->check   = 0x00;

   memset(&udpaux, 0, sizeof(struct __auxhdr));
   udpaux.saddr   = __ip->saddr;
   udpaux.daddr   = __ip->daddr;
   udpaux.useless = 0x0;
   udpaux.proto   = IPPROTO_UDP;
   udpaux.udpsiz  = htons(__size - SIZE_IP);

   memcpy(&udpaux.udp, __udp, SIZE_UDP);
   __udp->check   = __checksum( (uint16 *) &udpaux, (__size - SIZE_IP));

#else
   __ip->ip_src   = __source->sin_addr;
   __ip->ip_dst   = __target->sin_addr;
   __ip->ip_v     = 0x04;
   __ip->ip_hl    = 0x05;
   __ip->ip_ttl   = pkt->ttl;
   __ip->ip_id    = htons(rand() % 0xFFFF);
   __ip->ip_p     = IPPROTO_UDP;
   __ip->ip_len   = __size; /* HeaderIP and headerUDP: 28 bytes */
   __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);

   __udp->uh_sport= __source->sin_port;
   __udp->uh_dport= __target->sin_port;
   __udp->uh_ulen = htons(__size - SIZE_IP);
   __udp->uh_sum  = 0x00;

   memset(&udpaux, 0, sizeof(struct __auxhdr));
   udpaux.saddr   = __ip->ip_src.s_addr;
   udpaux.daddr   = __ip->ip_dst.s_addr;
   udpaux.useless = 0x0;
   udpaux.proto   = IPPROTO_UDP;
   udpaux.udpsiz  = htons(__size - SIZE_IP);

   memcpy(&udpaux.udp, __udp, SIZE_UDP);
   __udp->uh_sum  = __checksum( (uint16 *) &udpaux, (__size - SIZE_IP));

#endif
}


#if !defined(WEAK_GCC)
__hot__ inline static void *__send() {
#else
inline static void *__send() {
#endif

   auto signed int sock;
   struct sockaddr_in source;

   pthread_mutex_lock(&__mutex);
   /* RAW socket */
   if ( !( sock = __socketPool(true, 0, false)) ) return NULL;
   pthread_mutex_unlock(&__mutex);
   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 40] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));
   __lookup(&source, pkt->src, pkt->srcport, true);
   __packing(cbuffer, (uint16) sizeof(cbuffer), &source, _data.target);

   bool isConted = false;
   auto uint32 count = pkt->counter;
   volatile unsigned counter = 1;
   unsigned _sizeof = sizeof(struct sockaddr_in);

   auto char address[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);

   __cache(&sock);
   __cache(cbuffer);
   __cache(&_sizeof);
   __cache(&_data.target);

   do {
      show("(%d) Sending UDP packet to host [%s] on port %d with %d bytes: TTL=%d\n", \
      counter++, address, htons(_data.target->sin_port), (uint32) sizeof(cbuffer), pkt->ttl);

      if ( hardfalse(sendto(sock, cbuffer, (uint32) sizeof(cbuffer), 0,\
      (struct sockaddr *) _data.target, _sizeof) < 0) ) {
         log("Error on send UDP packet.\n\n");
         kill(getpid(), SIGALRM);
         break;
        }

      if (pkt->continuous) sleep(1);
      else if (pkt->flood) usleep(pkt->flood*100);
      else if (pkt->counter) {
         isConted = true;
         usleep(50000);
      }
      if (!(--count)) break;
   } while (pkt->continuous || pkt->flood || isConted);
   return NULL;
}


#if !defined(WEAK_GCC)
__hot__ inline static void *__burst() {
#else
inline static void *__burst() {
#endif

   register signed int sock;
   struct sockaddr_in source;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock = __socketPool(true, 0, false)) ) return NULL;
   pthread_mutex_unlock(&__mutex);
   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 40] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));
   __lookup(&source, pkt->src, pkt->srcport, true);
   __packing(cbuffer, (uint16) sizeof(cbuffer), &source, _data.target);

   auto char address[INET_ADDRSTRLEN] __nocommon__;
   inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);

   show("[BURST] Sending UDP packets to host [%s] on port %d with %d bytes...\n", \
   address, ntohs(_data.target->sin_port), (uint32) sizeof(cbuffer));

   register uint8 tsize = sizeof(struct sockaddr_in);
   register uint32 size = sizeof(cbuffer);
   register uint32 counter = pkt->counter;
   register uchar *buffer = cbuffer;
   register struct sockaddr_in *targ = _data.target;

   __SEND:
   if ( hardfalse(sendto(sock, buffer, size, 0, (struct sockaddr *) \
   targ, tsize) < 0))
      goto __EXIT;

   if (--counter) goto __SEND;
   goto __RETURN;

   __EXIT:
   log("Error on send UDP packet.\n\n");
   kill(getpid(), SIGALRM);

   __RETURN:
   return NULL;
}


bool udp( const char **pull __unused__ ) {

   signal(SIGINT, __sigcatch);
   signal(SIGALRM, __sigcatch);

   static char addressbuff[sizeof(struct sockaddr_in)*2] __nocommon__;
   _data.source = (struct sockaddr_in *) addressbuff;
   _data.target = (struct sockaddr_in *) addressbuff + sizeof(struct sockaddr_in);

   if (!__lookup(_data.source, pkt->src, pkt->srcport, true)) return false;

   if (pkt->listenMode & LISTEN_UDP) {
      __doListen();
      goto __OFF;
   }

   if (!__lookup(_data.target, pkt->dst, pkt->port, false)) return false;

   if (pkt->superFlood) {
      if ( !__threadPool(pkt->numThreads, &__burst, NULL) ) return false;
   } else {
      if ( !__threadPool(pkt->numThreads, &__send, NULL) ) return false;
   }

   pthread_exit(0);
   __OFF:
   return true;
}

