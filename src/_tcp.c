/*......,,,,,,,.............................................................
*
* @@NAME:     Module TCP
* @@VERSION:  1.0.3
* @@DESC:     TCP source file (this file is part of Nsoq tool).
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

struct __data _data;   /* Sender bulk */
#define BIGBUFF 10240

__malloc__ static const char *__tagging( struct tcphdr *__tcp ) {

   char *__buff = (char *) calloc(1, 64);

#if defined(__LINUX_SYSTEM__)
   if (!__tcp->rst && 
      !__tcp->fin && 
      !__tcp->psh && 
      !__tcp->ack && 
      !__tcp->syn &&
      !__tcp->urg ) {
         snprintf(__buff, 11, "NULL FLAGS");
   
   } else {
      if (__tcp->rst) snprintf(__buff, 5, "|RST");
      if (__tcp->fin) strncat(__buff, "|FIN", 4);
      if (__tcp->psh) strncat(__buff, "|PSH", 4);
      if (__tcp->ack) strncat(__buff, "|ACK", 4);
      if (__tcp->syn) strncat(__buff, "|SYN", 4);
      if (__tcp->urg) strncat(__buff, "|URG", 4);
   }
#else
   if (!__tcp->th_flags) snprintf(__buff, 11, "NULL FLAGS");
   else {
      if (__tcp->th_flags & TCP_RST) snprintf(__buff, 5, "|RST");
      if (__tcp->th_flags & TCP_FIN) strncat(__buff, "|FIN", 4);
      if (__tcp->th_flags & TCP_PSH) strncat(__buff, "|PSH", 4);
      if (__tcp->th_flags & TCP_ACK) strncat(__buff, "|ACK", 4);
      if (__tcp->th_flags & TCP_SYN) strncat(__buff, "|SYN", 4);
      if (__tcp->th_flags & TCP_URG) strncat(__buff, "|URG", 4);
   }
#endif

   return __buff;
}


static void __doListenConnections( void ) {

   uchar recvbuff[pkt->buffsize + BIGBUFF] __nocommon__;
   char address[INET_ADDRSTRLEN] __nocommon__; // motd[30];
   struct sockaddr_in remote;
   unsigned size = sizeof(struct sockaddr_in);
   signed int sock, nsock, __input = 0;

   struct timeval _times;
   fd_set arrived;

   log("Listening for TCP connections on local port (%d):\n", pkt->srcport);

   __AGAIN:
   /* TCP STREAM socket */
   if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) return;

   if ( (bind(sock, (struct sockaddr *) _data.source, 
   sizeof(struct sockaddr))) < 0) {
      log("Error on bind action.\n\n"); 
      kill(getpid(), SIGALRM);
      return;
   }

   if (listen(sock, 1) < 0) {
      log("Error on Listen. \n\n"); 
      kill(getpid(), SIGALRM);
      return;
   }

   if ( (nsock = accept(sock, (struct sockaddr *) &remote, &size)) <= 0){
      log("Error on accept connection.\n\n"); 
      kill(getpid(), SIGALRM);
      return;
   }

   close(sock);
   sock = nsock;
   __sysdate();

   inet_ntop(AF_INET, &(remote.sin_addr), address, INET_ADDRSTRLEN);
   log("\n\n(%02d:%02d:%02d) Connected: Opened by Host [%s]\n",
   _t->tm_hour, _t->tm_min, _t->tm_sec, address);

   _times.tv_sec = 0;
   _times.tv_usec = 500;
   FD_ZERO(&arrived);
   FD_SET(STDIN_FILENO, &arrived);

   if ( !select(STDIN_FILENO+1, &arrived, NULL, NULL, &_times)) pass;
   else
      while ( (__input = read(STDIN_FILENO, &recvbuff, BIGBUFF)) > 0)
         write(sock, &recvbuff, __input);

   FD_ZERO(&arrived);
   FD_SET(sock, &arrived);
   while ( FD_ISSET (sock, &arrived)) {

      memset(recvbuff, 0, sizeof(recvbuff));
      select(sock+1, &arrived, NULL, NULL, NULL);

      __sysdate();
      if ( ( __input = read(sock, recvbuff, sizeof(recvbuff))) <= 0 ) 
         FD_CLR(sock, &arrived);
      else write(STDOUT_FILENO, recvbuff, __input);

      if (FD_ISSET (STDIN_FILENO, &arrived))   /* More stdin muck */
         if ( read (STDIN_FILENO, recvbuff, sizeof(recvbuff)) <= 0 ) 
            FD_CLR(sock, &arrived);
   }

   log("\n[Connection closed]. Listening again..\n");
   close(sock);

   sleep(1);
   goto __AGAIN;
}


#if defined(__BSD_SYSTEM__)
static void __bsd_listen ( uchar *args,
                           const struct pcap_pkthdr *hdr,
                           const uchar *recvbuff )
{

   struct ip *ip      = (struct ip *) (recvbuff + SIZE_ETH);
   struct tcphdr *tcp = (struct tcphdr *) (recvbuff + SIZE_IP+ SIZE_ETH);

   __sysdate();
   char aux[20] __nocommon__, address[INET_ADDRSTRLEN] __nocommon__;

   if (ip->ip_p != IPPROTO_TCP) goto __MY_END;
   if ((args) && (_data.target->sin_addr.s_addr != ip->ip_src.s_addr) ) 
      goto __MY_END;
   if ( pkt->port == ntohs(tcp->th_sport) ) goto __CATCHED;
   if ( ntohs(tcp->th_dport) != pkt->srcport ) goto __MY_END;

   __CATCHED:
   memset(aux, 0, sizeof(aux));
   inet_ntop(AF_INET, &(ip->ip_src), address, INET_ADDRSTRLEN);

   const char *type = __tagging(tcp);
   if (!args) {
      show("(%02d:%02d:%02d) Received TCP (%s) packet from host [%s:%d] with %d Bytes: TTL=%d\n",
      _t->tm_hour, _t->tm_min, _t->tm_sec, type, address,ntohs(tcp->th_sport),
      ntohs(ip->ip_len), ip->ip_ttl);
   } else {
      show("  --> Received TCP (%s) packet from host [%s:%d] with %d Bytes: TTL=%d\n\n",
      type, address, ntohs(tcp->th_sport), ntohs(ip->ip_len), ip->ip_ttl);
   }

   if (type) free((void *) type);
   if (pkt->packetDisplay) __show_packet(&recvbuff[14], ntohs(ip->ip_len));
   if (args) pcap_breakloop(__session);

   __MY_END:
   pass;
}
#endif


inline static void __doListen( void ) {

#if defined(__BSD_SYSTEM__)
   char *eth, err_buff[PCAP_ERRBUF_SIZE];

   if (pkt->port)
      show("Listening for TCP data on local port (%d) or remote port (%d) [Capturing size %d bytes]:\n",
      pkt->srcport, pkt->port, (uint32) pkt->buffsize + 128);
   else show("Listening for TCP data on local port (%d) [Capturing size %d bytes]:\n",
      pkt->srcport, (uint32) pkt->buffsize + 128);

   if ( !(eth = pcap_lookupdev(err_buff)) ) {
      log("ERROR on grab system's interface. Exiting..\n\n");
      kill(getpid(), SIGALRM);
      goto __STOP;
   }

   if ( !(__session = 
   pcap_open_live(eth,pkt->buffsize + 128, true, 1, err_buff)) ) {
      log("Couldn't open device %s: Detail: %s\n", eth, err_buff);
      kill(getpid(), SIGALRM);
      goto __STOP;
   }

   pcap_loop(__session, -1, __bsd_listen, NULL);

#else

   register uint32 sock;
   /* TCP RAW socket */
   if ( !( sock = __socketPool(false, __TCP_MODE__, false)) ) return;

   __set_hdrincl(sock);

   uchar recvbuff[pkt->buffsize + 128];
   register uint32 size = sizeof(recvbuff);
   struct sockaddr_in remote;
   unsigned _sizeof = sizeof(struct sockaddr_in);

   const char *type;
   char address[INET_ADDRSTRLEN];
   struct iphdr *recvip = (struct iphdr *) recvbuff;
   struct tcphdr *recvtcp = (struct tcphdr *) (recvbuff + SIZE_IP);

   if (pkt->port) 
      show("Listening for TCP data on local port (%d) or remote port (%d) [Capturing size %d bytes]:\n", 
      pkt->srcport, pkt->port, size);
   else 
      show("Listening for TCP data on local port (%d) [Capturing size %d bytes]:\n",
      pkt->srcport, size);

   __LISTEN:
   memset(recvbuff, 0, size);

   if ( hardfalse(recvfrom(sock, recvbuff, size, 0, \
   (struct sockaddr *) &remote, &_sizeof) < 0) ) {
      log("ERROR on received data.\n\n");
      kill(getpid(), SIGALRM);
      goto __STOP;
   }

   if (recvip->protocol != IPPROTO_TCP) goto __LISTEN;
   if ( (pkt->port) && (ntohs(recvtcp->source) == pkt->port) ) goto __CATCH;
   if (ntohs(recvtcp->dest) != pkt->srcport) goto __LISTEN;

   __CATCH:
   __sysdate();
   type = __tagging(recvtcp);
   inet_ntop(AF_INET, &(recvip->saddr), address, INET_ADDRSTRLEN);
   show("(%02d:%02d:%02d) Received TCP (%s) packet from host [%s:%d] with %d Bytes: TTL=%d\n\n", \
   _t->tm_hour, _t->tm_min, _t->tm_sec, type, address, ntohs(recvtcp->source),
   ntohs(recvip->tot_len), recvip->ttl);
   if (type) free((void *) type);

   if (pkt->packetDisplay) __show_packet(recvbuff, ntohs(recvip->tot_len));
   goto __LISTEN;

#endif
   __STOP:
   pass;
}



inline static struct tcphdr *__packing( uchar *__buffer,
                              const uint16 __size,
                              const struct sockaddr_in *__source,
                              const struct sockaddr_in *__target ) {

   struct tcphdr *__tcp = (struct tcphdr *) (__buffer + SIZE_IP);
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
      uchar data[__size - (SIZE_IP + SIZE_TCP)];
#endif
   } __packed__ tcpaux;

#if defined(__LINUX_SYSTEM__)
   struct iphdr *__ip = (struct iphdr *) __buffer;

   __ip->saddr   = __source->sin_addr.s_addr;
   __ip->daddr   = __target->sin_addr.s_addr;
   __ip->version = 0x04;
   __ip->frag_off= 0x00;
   __ip->ihl     = 0x05;
   __ip->ttl     = pkt->ttl;
   __ip->id      = htons(rand() % 0xFFFF);
   __ip->protocol= IPPROTO_TCP;
   __ip->tot_len = htons(__size); /* HeaderIP and headerTCP: 40 bytes */
   __ip->check   = __checksum((uint16 *) __ip, SIZE_IP);

   __tcp->source = __source->sin_port;
   __tcp->dest   = __target->sin_port;
   __tcp->seq    = (pkt->tcpType & TCP_SYN) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
   __tcp->ack_seq= (pkt->tcpType & TCP_ACK) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
   __tcp->doff   = 0x5;
   __tcp->res2   = 0x0;
   __tcp->fin    = (pkt->tcpType & TCP_FIN) ? 0x01 : 0x00;
   __tcp->syn    = (pkt->tcpType & TCP_SYN) ? 0x01 : 0x00;
   __tcp->rst    = (pkt->tcpType & TCP_RST) ? 0x01 : 0x00;
   __tcp->psh    = (pkt->tcpType & TCP_PSH) ? 0x01 : 0x00;
   __tcp->ack    = (pkt->tcpType & TCP_ACK) ? 0x01 : 0x00;
   __tcp->urg    = (pkt->tcpType & TCP_URG) ? 0x01 : 0x00;
   __tcp->window = htons(1024); 
   /* I'll set size window to 1024. Don't care about is. */
   __tcp->urg_ptr= 0x00;
   __tcp->check  = 0;

   memset(&tcpaux, 0, sizeof(struct __auxhdr));
   tcpaux.saddr   = __ip->saddr;
   tcpaux.daddr   = __ip->daddr;
   tcpaux.useless = 0x0;
   tcpaux.proto   = IPPROTO_TCP;
   tcpaux.tcpsiz  = htons(__size - SIZE_IP);

   memcpy(&tcpaux.tcp, __tcp, SIZE_TCP);
   __tcp->check   = __checksum( (uint16 *) &tcpaux, (__size - SIZE_IP));

#else
   struct ip *__ip = (struct ip *) __buffer;

   __ip->ip_src   = __source->sin_addr;
   __ip->ip_dst   = __target->sin_addr;
   __ip->ip_v     = 0x04;
   __ip->ip_off   = 0x00;
   __ip->ip_hl    = 0x05;
   __ip->ip_ttl   = pkt->ttl;
   __ip->ip_id    = htons(rand() % 0xFFFF);
   __ip->ip_p     = IPPROTO_TCP;
   __ip->ip_len   = __size; /* HeaderIP and headerTCP --> 40 bytes */
   __ip->ip_sum   = __checksum((uint16 *) __ip, SIZE_IP);

   __tcp->th_sport= __source->sin_port;
   __tcp->th_dport= __target->sin_port;
   __tcp->th_seq  = (pkt->tcpType & TCP_SYN) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
   __tcp->th_ack  = (pkt->tcpType & TCP_ACK) ? htonl(rand() % 0xFFFFFFFF) : 0x00000000;
   __tcp->th_x2   = 0x0;
   __tcp->th_off  = 0x5;
   __tcp->th_flags |= (pkt->tcpType & TCP_FIN) ? TCP_FIN : 0x00;
   __tcp->th_flags |= (pkt->tcpType & TCP_SYN) ? TCP_SYN : 0x00;
   __tcp->th_flags |= (pkt->tcpType & TCP_RST) ? TCP_RST : 0x00;
   __tcp->th_flags |= (pkt->tcpType & TCP_PSH) ? TCP_PSH : 0x00;
   __tcp->th_flags |= (pkt->tcpType & TCP_ACK) ? TCP_ACK : 0x00;
   __tcp->th_flags |= (pkt->tcpType & TCP_URG) ? TCP_URG : 0x00;
   __tcp->th_win   = htons(1024); 
   /* I'll set size window to 1024. Don't care about is. */
   __tcp->th_urp   = 0x00;
   __tcp->th_sum   = 0;

   tcpaux.saddr    = __ip->ip_src.s_addr;
   tcpaux.daddr    = __ip->ip_dst.s_addr;
   tcpaux.useless  = 0x0;
   tcpaux.proto    = IPPROTO_TCP;
   tcpaux.tcpsiz   = htons(__size - SIZE_IP);

   memcpy(&tcpaux.tcp, __tcp, SIZE_TCP);
   __tcp->th_sum   = __checksum( (uint16 *) &tcpaux, (__size - SIZE_IP));
#endif
   return __tcp;
}


inline static void __doResponse( const uint32 sock ) {

#if defined(__BSD_SYSTEM__)
   char *eth, err_buff[PCAP_ERRBUF_SIZE];
   void *__breakout = (void *) 0xFF;

   if ( !(eth = pcap_lookupdev(err_buff)) ) {
      log("ERROR on grab system's interface. Exiting..\n\n");
      kill(getpid(), SIGALRM);
      goto __DOWN;
   }

   if ( !(__session = 
   pcap_open_live(eth, pkt->buffsize + 128, true, 1, err_buff)) ) {
      log("Couldn't open device %s: Detail: %s\n", eth, err_buff);
      kill(getpid(), SIGALRM);
      goto __DOWN;
   }

   pcap_loop(__session, -1, __bsd_listen, __breakout);

   __DOWN:
   pass;

#else
   uchar recvbuff[pkt->buffsize + 52];
   memset(recvbuff, 0, sizeof(recvbuff));

   char address[INET_ADDRSTRLEN];
   socklen_t _sizeof = sizeof(struct sockaddr_in);
   struct sockaddr_in remote;
   struct timeval _times;

   struct iphdr *recvip = (struct iphdr *) recvbuff;
   struct tcphdr *recvtcp = (struct tcphdr *) (recvbuff + SIZE_IP);

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

      if ( hardfalse(recvfrom(sock, recvbuff, sizeof(recvbuff), 0,
      (struct sockaddr *) &remote, &_sizeof) < 0) ) {
         log("ERROR on received data.\n\n");
         kill(getpid(), SIGALRM);
         break;
      }

   } while((recvip->protocol != IPPROTO_TCP) ||
         (_data.target->sin_addr.s_addr != recvip->saddr) ||
         (_data.target->sin_port != recvtcp->source));

   inet_ntop(AF_INET, &(recvip->saddr), address, INET_ADDRSTRLEN);
   const char *type = __tagging(recvtcp); 

   show("  --> Received TCP (%s) packet from host [%s] with %d Bytes: TTL=%d\n",
   type, address, ntohs(recvip->tot_len), recvip->ttl);

   if (type) free((void *) type);
   if (pkt->packetDisplay) __show_packet(recvbuff, ntohs(recvip->tot_len));
#endif
}


inline static void *__doSimpleConnection() {

   uint32 sock;

   pthread_mutex_lock(&__mutex);
   /* TCP STREAM socket */
   if ( !( sock = __socketPool(false, __TCP_MODE__, true)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   unsigned __sizeof = sizeof(struct sockaddr);
   char address[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);

   log("Connecting to host [%s] on port %d...\n", 
   address, ntohs(_data.target->sin_port));

   char buff[BIGBUFF];
   struct timeval _times;
   fd_set beep;
   register signed int __limit = 0, __input = 0;

   __sysdate();
   _times.tv_sec = 1;
   _times.tv_usec = 0;
   FD_ZERO(&beep);
   FD_SET(sock, &beep);

   if ( connect(sock, (struct sockaddr *) _data.target, __sizeof) < 0) {
      log("Unable to connect on host. Connection refused.\n");
      kill(getpid(), SIGALRM);
      pthread_exit(NULL);
   }

   log("\n(%02d:%02d:%02d) Connected on Host [%s]:\n",
   _t->tm_hour, _t->tm_min, _t->tm_sec, address);

   while ( select(sock+1, &beep, NULL, NULL, &_times) ) {
      __input = read(sock, &buff, BIGBUFF);
      write(STDOUT_FILENO, &buff, __input);
   }


   _times.tv_sec = 1;
   _times.tv_usec = 0;
   FD_ZERO(&beep);
   FD_SET(sock, &beep);
   __input = 0;

   do {
      memset(buff, 0, sizeof(buff));
      __limit = read(STDIN_FILENO, &buff, sizeof(buff));
      write(sock, &buff, __limit);

      if ( !select(sock+1, &beep, NULL, NULL, &_times)) {
         FD_ZERO(&beep);
         FD_SET(sock, &beep);
      } else {
         if ( (__input = read(sock,&buff,sizeof(buff))) <= 0) FD_CLR(sock,&beep);
         else write(STDOUT_FILENO, buff, __input);
      }

      if (FD_ISSET (0, &beep)) /* More stdin muck */
         if ( read (STDIN_FILENO, buff, sizeof(buff)) <= 0 ) FD_CLR(sock, &beep);
   } while ( (FD_ISSET (sock, &beep)) && __limit);


   log("[Closed connection]\n");
   pthread_exit(NULL);
}


#if !defined(WEAK_GCC)
__call__ inline static void *__send() {
#else
inline static void *__send() {
#endif

   uint32 nsock, sock;

   pthread_mutex_lock(&__mutex);
   /* RAW socket*/
   if ( !( sock  = __socketPool(true, 0, false)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   /* TCP RAW socket */
   if ( !( nsock = __socketPool(false, __TCP_MODE__, false)) ) {
      pthread_mutex_unlock(&__mutex);
      pthread_exit(NULL);
   }
   pthread_mutex_unlock(&__mutex);

   __set_hdrincl(sock);

   uchar cbuffer[pkt->buffsize + 52] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));

   struct tcphdr *__tcp = __packing(cbuffer, (uint16) sizeof(cbuffer),
                          _data.source, _data.target);

   bool isConted = false;
   register uint32 count = pkt->counter;
   volatile unsigned counter = 1;
   unsigned _sizeof = sizeof(struct sockaddr_in);

   char address[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);

   __cache(&sock);
   __cache(&cbuffer);
   __cache(&_sizeof);
   __cache(&_data.target);

#if defined(__BSD_SYSTEM__)
   bool ret;
#endif

   do {

#if defined(__BSD_SYSTEM__)
   ret = true;
   if ( hardtrue( (!pkt->ignoreReplies)) )
      if ( !(ret = __threadPool(1, &__doResponse, NULL)) ) return false;
#endif

      const char *type = __tagging(__tcp);
      show("(%d) Sending TCP (%s) packet to host [%s] on port %d with %d bytes: TTL=%d\n",
      counter++, type, address, ntohs(_data.target->sin_port), 
      (uint32) sizeof(cbuffer), pkt->ttl);

      if (type) free((void *) type);

      if ( hardfalse(sendto(sock, cbuffer, sizeof(cbuffer), 0,
      (struct sockaddr *) _data.target, _sizeof) < 0) ) {
         log("Error on send TCP packet.\n\n");
         kill(getpid(), SIGALRM);
         break;
      }

#if defined(__BSD_SYSTEM__)
      pthread_join((pthread_t) ret, NULL);
#else
      if ( hardtrue( (!pkt->ignoreReplies)) ) __doResponse(nsock);
#endif

      if (pkt->continuous) sleep(1);
      else if (pkt->flood) usleep(pkt->flood*100);
      else if (pkt->counter) {
         isConted = true;
         usleep(50000);
      }
      if (!(--count)) break;
      __packing(cbuffer, (uint16) sizeof(cbuffer), _data.source, _data.target);
   } while (pkt->continuous || pkt->flood || isConted);

   pthread_exit(NULL);
}


#if !defined(WEAK_GCC)
__call__ inline static void *__burst() {
#else
inline static void *__burst() {
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

   uchar cbuffer[pkt->buffsize + 52] __nocommon__;
   memset(cbuffer, 0, sizeof(cbuffer));

   struct tcphdr *__tcp = __packing(cbuffer, (uint16) sizeof(cbuffer), 
                          _data.source, _data.target);

   char address[INET_ADDRSTRLEN] __nocommon__;
   inet_ntop(AF_INET, &(_data.target->sin_addr), address, INET_ADDRSTRLEN);

   const char *type = __tagging(__tcp);
   show("[BURST] Sending TCP (%s) packets to host [%s] on port %d with %d bytes...\n",
   type, address, ntohs(_data.target->sin_port), (uint32) sizeof(cbuffer));
   if (type) free((void *) type);

   register uint8 tsize = sizeof(struct sockaddr_in);
   register uint32 size = sizeof(cbuffer);
   register uint32 counter = pkt->counter;
   register uchar *buffer = cbuffer;
   register struct sockaddr_in *targ = _data.target;

   __SEND:
   if ( hardfalse(sendto(sock, buffer, size, 0, (struct sockaddr *)
   targ, tsize) < 0)) goto __EXIT;

   __packing(cbuffer, (uint16) sizeof(cbuffer), _data.source, _data.target);
   if (--counter) goto __SEND;
   goto __RETURN;

   __EXIT:
   log("Error on send TCP packet.\n\n");
   kill(getpid(), SIGALRM);

   __RETURN:
   pthread_exit(NULL);
}


bool tcp(const char **pull __unused__ ) {

   signal(SIGINT, __sigcatch);
   signal(SIGALRM, __sigcatch);

   _data.source = (struct sockaddr_in *) addressbuff;
   _data.target = (struct sockaddr_in *) addressbuff + sizeof(struct sockaddr_in);

   if (!__lookup(_data.source, pkt->src, pkt->srcport, true)) return false;

   if (pkt->listenMode & LISTEN_TCP) {
      __doListen();
      goto __FINISHTCP;
   } else if (pkt->listenMode & LISTEN_TCP_CON) {
      __doListenConnections();
      goto __FINISHTCP;
   }

   if (!__lookup(_data.target, pkt->dst, pkt->port, false)) return false;

   if (pkt->tcpType & TCP_CON) { 
      if ( !__threadPool(pkt->numThreads, &__doSimpleConnection, NULL) ) return false;
   } else if (pkt->superFlood) {
      if ( !__threadPool(pkt->numThreads, &__burst, NULL) ) return false;
   } else {
      if ( !__threadPool(pkt->numThreads, &__send, NULL) ) return false;
   }

   __FINISHTCP:
   return true;
}

