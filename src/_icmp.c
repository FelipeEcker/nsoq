/*......,,,,,,,.............................................................
*
* @@NAME:     Module ICMP
* @@VERSION:  1.0.2
* @@DESC:     ICMP source file (this file is part of MpTcp tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     22/11/2012 14:20:00
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2013.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/

#include "../include/core.h"

#define __tagging( __tag,type ) do {                                \
   if ((type == 0x08) || (type & ICMP_ECHO_REQ)) pass;              \
   else if ((type == 0x00) || (type & ICMP_ECHO_REPLY)) __tag++;    \
   else if ((type == 0x04) || (type & ICMP_SRC_QUENCH)) __tag += 2; \
   else if ((type == 0x11) || (type & ICMP_MASK_REQ)) __tag += 3;   \
   else if ((type == 0x12) || (type & ICMP_MASK_REPLY)) __tag += 4; \
   else if ((type == 0x0F) || (type & ICMP_INFO)) __tag += 5;       \
   else if ((type == 0x0D) || (type & ICMP_TIME_REQ)) __tag += 6;   \
   else if (type == 0x0E) __tag += 7;                               \
   else if (type == 0x10) __tag += 8;                               \
   else __tag += 9;                                                 \
   } while(0)


static struct __data _data;   /* Sender bulk */

const char *tags[] = {
   "ICMP Type 8 (Echo Request)",
   "ICMP Type 0 (Echo Reply)",
   "ICMP Type 4 (Source Quench)",
   "ICMP Type 17 (Mask Request)",
   "ICMP Type 18 (Mask Reply)",
   "ICMP Type 15 (Info Request)",
   "ICMP Type 13 (Timestamp Request)",
   "ICMP Type 14 (Timestamp Reply)",
   "ICMP Type 16 (Info Reply)",
   "Unknown ICMP data"
};


#if defined(__BSD_SYSTEM__)
static void __bsd_listen (   uchar *args, 
                     const struct pcap_pkthdr *hdr, 
                     const uchar *recvbuff ) 
{

   /* auto struct ether_header *h = (struct ether_header *) recvbuff; */
   auto struct ip *ip        = (struct ip *) (recvbuff + SIZE_ETH);
   auto struct icmp *icmp    = (struct icmp *) (recvbuff + SIZE_IP + SIZE_ETH);
   auto struct in_addr *mask = (struct in_addr *) (recvbuff + SIZE_ICMP + SIZE_IP + SIZE_ETH);

   const char **tag;
   tag = tags;
   __tagging(tag, (uint32) icmp->icmp_type);
   __sysdate();

   auto char aux[20] __nocommon__, address[INET_ADDRSTRLEN] __nocommon__;

   if (ip->ip_p == IPPROTO_ICMP) {

      memset(aux, 0, sizeof(aux));
      if (icmp->icmp_type == 0x12) {
         inet_ntop(AF_INET, &(*mask), address, INET_ADDRSTRLEN);
         snprintf(aux, sizeof(aux)-1," [%s]", address);
      }

      inet_ntop(AF_INET, &(ip->ip_src), address, INET_ADDRSTRLEN);

      show("(%02d:%02d:%02d) Received packet %s%s from (%s) with %d bytes: TTL=%d\n", \
      _t->tm_hour, _t->tm_min, _t->tm_sec, *tag, aux, address, 
      ntohs(ip->ip_len), ip->ip_ttl);

      recvbuff += 14;
      if (pkt->packetDisplay) __show_packet(recvbuff, ntohs(ip->ip_len));
   }
}
#endif


static void __doListen( void ) {

#if defined(__BSD_SYSTEM__)
   auto char *eth, err_buff[PCAP_ERRBUF_SIZE];

   show("Listening for ICMP data [Capturing size %d bytes]:\n", 
   (uint32) pkt->buffsize + 512);

   if ( !(eth = pcap_lookupdev(err_buff)) ) {
      log("ERROR on grab system's interface. Exiting..\n\n");
      kill(getpid(), SIGALRM);
      goto __BREAK;
   }

   if ( !(__session = 
   pcap_open_live(eth, pkt->buffsize + 512, true, 1, err_buff)) ) {
      log("Couldn't open device %s: Detail: %s\n", eth, err_buff);
      kill(getpid(), SIGALRM);
      goto __BREAK;
   }

   pcap_loop(__session, -1, __bsd_listen, NULL);

#else
   auto signed int sock;
   /* ICMP RAW socket*/
   if ( !( sock = __socketPool(false, __ICMP_MODE__, false)) ) return; 

   uchar recvbuff[pkt->buffsize + 512] __nocommon__;
   auto struct iphdr *ip = (struct iphdr *) recvbuff;
   auto struct icmphdr *icmp = (struct icmphdr *) (recvbuff + SIZE_IP);
   auto struct in_addr *mask = (struct in_addr *) (recvbuff+SIZE_IP+SIZE_ICMP);

   auto char aux[20] __nocommon__, address[INET_ADDRSTRLEN] __nocommon__;
   auto struct sockaddr_in remote;
   unsigned size = sizeof(struct sockaddr_in);
   const char **tag;

   __cache(&sock);
   __cache(&remote);
   __cache(&size);
   __cache(&recvbuff);

   show("Listening for ICMP data [Capturing size %d bytes]:\n", 
   (uint32) sizeof(recvbuff));

   __LISTENAGAIN:
   memset(recvbuff, 0, sizeof(recvbuff));
   if ( (recvfrom(sock, recvbuff, sizeof(recvbuff), 0,
   (struct sockaddr *) &remote, &size)) < 0 ) {
      log("ERROR on received data.\n\n");
      kill(getpid(), SIGALRM);
      goto __BREAK;
   }

   tag = tags;

   __tagging(tag, (uint32) icmp->type);
   __sysdate();

   memset(aux, 0, sizeof(aux));

   if (icmp->type == 0x12) {
      inet_ntop(AF_INET, &(*mask), address, INET_ADDRSTRLEN);
      snprintf(aux, sizeof(aux)-1," [%s]", address);
   }

   inet_ntop(AF_INET, &(remote.sin_addr), address, INET_ADDRSTRLEN);

   show("(%02d:%02d:%02d) Received packet %s%s from (%s) with %d bytes: TTL=%d\n", \
   _t->tm_hour, _t->tm_min, _t->tm_sec, *tag, aux,
   address, ntohs(ip->tot_len), ip->ttl);

   if (pkt->packetDisplay) __show_packet(recvbuff, ntohs(ip->tot_len));
   goto __LISTENAGAIN;

#endif
   __BREAK:
   pass;
}


inline static void __packing( const uchar *__buffer, const uint32 __size ) {

   if (pkt->icmpType & ICMP_MASK_REPLY) {
      struct in_addr *mask = (struct in_addr *) (__buffer + SIZE_IP + SIZE_ICMP);
      inet_pton(AF_INET, pkt->icmpMask, mask);
   }

#if defined(__LINUX_SYSTEM__)
   struct iphdr *__ip = (struct iphdr *) __buffer;
   struct icmphdr *__icmp = (struct icmphdr *) (__buffer + SIZE_IP);

   __ip->saddr    = _data.source->sin_addr.s_addr;
   __ip->daddr    = _data.target->sin_addr.s_addr;
   __ip->version  = 0x04;
   __ip->ihl      = 0x05;
   __ip->ttl      = pkt->ttl;
   __ip->id       = htons(rand() % 0xFFFF);
   __ip->protocol = IPPROTO_ICMP;
   __ip->tot_len  = htons(__size); /* HeaderIP and headerICMP: 28 bytes */
   __ip->check    = __checksum((uint16 *) __ip, SIZE_IP);

   if (pkt->icmpType & ICMP_ECHO_REQ)          __icmp->type = 0x08;
   else if (pkt->icmpType & ICMP_ECHO_REPLY)   __icmp->type = 0x00;
   else if (pkt->icmpType & ICMP_INFO)         __icmp->type = 0x0F;
   else if (pkt->icmpType & ICMP_TIME_REQ)     __icmp->type = 0x0D;
   else if (pkt->icmpType & ICMP_SRC_QUENCH)   __icmp->type = 0x04;
   else if (pkt->icmpType & ICMP_MASK_REQ)     __icmp->type = 0x11;
   else if (pkt->icmpType & ICMP_MASK_REPLY)   __icmp->type = 0x12;

   __icmp->code             = 0;
   __icmp->un.echo.id       = htons(rand() % 0xFFFF);
   __icmp->un.echo.sequence = htons(rand() % 0xFFFF);

   __icmp->checksum = __checksum( (uint16 *) __icmp, 
                      SIZE_ICMP + sizeof(struct in_addr));

#else
   struct ip *__ip = (struct ip *) __buffer;
   struct icmp *__icmp = (struct icmp *) (__buffer + SIZE_IP);

   __ip->ip_src   = _data.source->sin_addr;
   __ip->ip_dst   = _data.target->sin_addr;
   __ip->ip_id    = htons(rand() % 0XFFFF);
   __ip->ip_v     = 0x04;
   __ip->ip_hl    = 0x05;
   __ip->ip_ttl   = pkt->ttl;
   __ip->ip_p     = IPPROTO_ICMP;
   __ip->ip_len   = __size; /* HeaderIP and headerICMP: 28 bytes */
   __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);

   if (pkt->icmpType & ICMP_ECHO_REQ)         __icmp->icmp_type = 0x08;
   else if (pkt->icmpType & ICMP_ECHO_REPLY)  __icmp->icmp_type = 0x00;
   else if (pkt->icmpType & ICMP_INFO)        __icmp->icmp_type = 0x0F;
   else if (pkt->icmpType & ICMP_TIME_REQ)    __icmp->icmp_type = 0x0D;
   else if (pkt->icmpType & ICMP_SRC_QUENCH)  __icmp->icmp_type = 0x04;
   else if (pkt->icmpType & ICMP_MASK_REQ)    __icmp->icmp_type = 0x11;
   else if (pkt->icmpType & ICMP_MASK_REPLY)  __icmp->icmp_type = 0x12;

   __icmp->icmp_code  = 0x00;
   __icmp->icmp_id    = htons(rand() % 0xFFFF);
   __icmp->icmp_seq   = htons(rand() % 0xFFFF);

   __icmp->icmp_cksum = __checksum( (uint16 *) __icmp, 
                        SIZE_ICMP + sizeof(struct in_addr));
#endif
}


inline static void __doResponse( register signed int sock ) {

   uchar recvbuff[pkt->buffsize + 40];
   memset(recvbuff, 0, sizeof(recvbuff));

   char address[INET_ADDRSTRLEN], __mask[INET_ADDRSTRLEN];
   unsigned _sizeof = sizeof(struct sockaddr_in);
#if defined(__LINUX_SYSTEM__)
   register struct iphdr *recvip = (struct iphdr *) recvbuff;
#else
   register struct ip *recvip = (struct ip *) recvbuff;
#endif
   register struct in_addr *mask = (struct in_addr *) (recvbuff + SIZE_IP + SIZE_ICMP);
   struct sockaddr_in remote;
   struct timeval _times;
   fd_set beep;

   _times.tv_sec = 4;
   _times.tv_usec = 0;
   FD_ZERO(&beep);
   FD_SET(sock, &beep);

   do {
      if ( !select(sock+1, &beep, NULL, NULL, &_times) ) {
         log("[Timeout]\n");
         kill(getpid(), SIGALRM);
         break;
      }

      if ( hardfalse(recvfrom(sock, recvbuff, sizeof(recvbuff), 0, \
      (struct sockaddr *) &remote, &_sizeof) < 0) ) {
         log("ERROR on received data.\n\n");
         kill(getpid(), SIGALRM);
         break;
      }

   } while (_data.target->sin_addr.s_addr != remote.sin_addr.s_addr);

#if defined(__LINUX_SYSTEM__)
   inet_ntop(AF_INET, &(recvip->saddr), address, INET_ADDRSTRLEN);
   if (pkt->icmpType & ICMP_ECHO_REQ) {
      show("  --> Received Echo Reply from host (%s) with %d Bytes: TTL=%d\n\n", \
      address, ntohs(recvip->tot_len), recvip->ttl);
   } else if (pkt->icmpType & ICMP_MASK_REQ) {
      inet_ntop(AF_INET, &(*mask), __mask, INET_ADDRSTRLEN);
      show("  --> Received Mask Reply from host (%s) with mask (%s): TTL=%d\n\n", \
      address, __mask, recvip->ttl);
   } else if (pkt->icmpType & ICMP_TIME_REQ) {
      show("  --> Received Timestamp Reply from host (%s) with %d Bytes: TTL=%d\n\n", \
      address, ntohs(recvip->tot_len), recvip->ttl);
   }

   if (pkt->packetDisplay) __show_packet(recvbuff, ntohs(recvip->tot_len));

#else
   inet_ntop(AF_INET, &(recvip->ip_src), address, INET_ADDRSTRLEN);
   if (pkt->icmpType & ICMP_ECHO_REQ) {
      show("  --> Received Echo Reply from host (%s) with %d Bytes: TTL=%d\n\n", \
      address, recvip->ip_len + SIZE_IP, recvip->ip_ttl);
   } else if (pkt->icmpType & ICMP_MASK_REQ) {
      inet_ntop(AF_INET, &(*mask), __mask, INET_ADDRSTRLEN);
      show("  --> Received Mask Reply from host (%s) with mask (%s): TTL=%d\n\n", \
      address, __mask, recvip->ip_ttl);
   } else if (pkt->icmpType & ICMP_TIME_REQ) {
      show("  --> Received Timestamp Reply from host (%s) with %d Bytes: TTL=%d\n\n", \
      address, recvip->ip_len + SIZE_IP, recvip->ip_ttl);
   }

   if (pkt->packetDisplay) __show_packet(recvbuff, (recvip->ip_len + SIZE_IP));
#endif
}


#if !defined(WEAK_GCC)
__hot__ inline static void *__send() {
#else
inline static void *__send() {
#endif

   auto signed int sock;

   pthread_mutex_lock(&__mutex);
   /* ICMP RAW socket*/
   if ( !( sock = __socketPool(false, __ICMP_MODE__, false)) ) return NULL;
   pthread_mutex_unlock(&__mutex);

   __set_broadcast(sock);
   __set_hdrincl(sock);

   const char **tag = tags;
   __tagging(tag, pkt->icmpType);

   bool isConted = false;
   register uint32 count = pkt->counter;
   unsigned _sizeof = sizeof(struct sockaddr_in);

   char address[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);

   uchar cbuffer[pkt->buffsize + 40] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));
   __packing(cbuffer, (uint32) sizeof(cbuffer));

   volatile unsigned counter = 1;
   __cache(&sock);
   __cache(&cbuffer);
   __cache(&_sizeof);
   __cache(&_data.target);

   do {
      show("[%d] Sending packet %s to host [%s] with %d bytes: TTL=%d...\n", \
      counter++, *tag, address, (uint32) sizeof(cbuffer), pkt->ttl);
      if ( hardfalse(sendto(sock, cbuffer, sizeof(cbuffer), 0,\
      (struct sockaddr *) _data.target, _sizeof) < 0) ) {
         log("Error on send ICMP packet.\n\n");
         kill(getpid(), SIGALRM);
         break;
      }

      if ( hardtrue( (!pkt->ignoreReplies) && (
         (pkt->icmpType & ICMP_ECHO_REQ) || 
         (pkt->icmpType & ICMP_MASK_REQ) || 
         (pkt->icmpType & ICMP_TIME_REQ)) 
      )) __doResponse(sock);

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

   pthread_mutex_lock(&__mutex);
   /* ICMP RAW socket*/
   if ( !( sock = __socketPool(false, __ICMP_MODE__, false)) ) return NULL;
   pthread_mutex_unlock(&__mutex);

   __set_broadcast(sock);
   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 40] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));
   __packing(cbuffer, (uint32) sizeof(cbuffer));

   const char **tag = tags;
   char address[INET_ADDRSTRLEN] __nocommon__;
   __tagging(tag, pkt->icmpType);
   inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);

   show("[BURST] Sending packets %s to host [%s] with %d bytes...\n",
   *tag, address, (uint32) sizeof(cbuffer));

   register uint8 tsize = sizeof(struct sockaddr_in);
   register uint32 counter = pkt->counter;
   register uchar *buffer = cbuffer;
   register uint32 size = sizeof(cbuffer);
   register struct sockaddr_in *targ = _data.target;

   __SEND:
   if ( hardfalse(sendto(sock, buffer, size, 0,
   (struct sockaddr *) targ, tsize) < 0)) 
      goto __EXIT;

   if (--counter) goto __SEND;
   goto __RETURN;

   __EXIT:

   log("Error on send ICMP packet.\n\n");
   kill(getpid(), SIGALRM);

   __RETURN:
   return NULL;
}


bool icmp( const char **pull __unused__ ) {

   signal(SIGINT, __sigcatch);
   signal(SIGALRM, __sigcatch);

   /* Does a listen ICMP.*/
   if (pkt->listenMode & LISTEN_ICMP) { 
      __doListen();
      goto __LEAVINGNOW;
   }

   static char addressbuff[sizeof(struct sockaddr_in) * 2] __nocommon__;
   _data.source = (struct sockaddr_in *) addressbuff;
   _data.target = (struct sockaddr_in *) (addressbuff + sizeof(struct sockaddr_in));

   if (!__lookup(_data.source, pkt->src, 0, true)) return false;
   if (!__lookup(_data.target, pkt->dst, 0, false)) return false;

   if (!pkt->superFlood) {
      if ( !__threadPool(pkt->numThreads, &__send, NULL) ) return false;
   } else {
      if ( !__threadPool(pkt->numThreads, &__burst, NULL) ) return false;
   }

   pthread_exit(0);

   __LEAVINGNOW:
   return true;
}

