/*......,,,,,,,.............................................................
*
* @@NAME:     NSOQ Project
* @@VERSION:  1.9.4
* @@DESC:     Main source file (this file is part of Nsoq tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     18/10/2014 12:30:00
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2014.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/


#include "../include/core.h"

static void __new( void ) __constructor__;
static void __exit( void ) __destructor__;
static bool __doExec( void * );

extern const char *__doConsistency( void ) __call__;
extern bool tcp( const char ** ) __call__;
extern bool udp( const char ** ) __call__;
extern bool icmp( const char ** ) __call__;
extern bool arp( const char ** ) __call__;
extern bool web( const char ** ) __call__;
extern bool irc( const char ** ) __call__;


#if defined(__cplusplus) && defined(CORE_H)
   #undef CORE_H
#endif
#if !defined(__PACKET__) && defined(CORE_H)
   #undef CORE_H
#endif

#ifdef __MSC_VER__
   #warning "MS Compiler is fail here.."
   #error [Missing Build] Unsuported compiler..
#elif defined(__BORLANDC__) && defined(__STDC__)
   #warning Keep mind: Compiler untested
#endif

#ifndef CORE_H
   #error The core Nsoq properties is missing. Aborting..
#endif

#define __info() do {                                                        \
   show("\n\n\t\t  - Network Security over a 'Q'rawler and RSOI Handler -");       \
   show("\n\n\tVer: %s - Released under GPL/GNU (Build Date: %s).", VERSION, DATEBUILD);\
   show("\n\tFinal Version compiled with libpthreads and libpcap (BSD).");   \
   show("\n\tMore includes that were used on compilation are available here too.");\
   show("\n\n\tQuestions or BUGs please mail me:");                          \
   show("\n\tFelipe Ecker (Khun) <khun@hexcodes.org>");                    \
   show("\n\n\n\n");                                                         \
   } while(0)


#define __spawn( __name ) do {                                               \
   show("Use: %s <OPTIONS>\n", __name);                                      \
   show("\n                           <Global> Options:");                   \
   show("\n  -d <Hostname>       Destination address");                      \
   show("\n  -s <Hostname>       Source address");                           \
   show("\n  -p <Port>           Destination port (remote)");                \
   show("\n  -P <Source port>    Source port (local)");                      \
   show("\n  -i <Interface>      Interface option.");                        \
   show("\n  -q <Number Packets> Number of packets to send");                \
   show("\n  -c                  Continuous mode (1 second delay)");         \
   show("\n  -F <Delay>          Flood mode (microseconds delay)");          \
   show("\n  -b                  Super Flood (CAUTION)");                    \
   show("\n  -n <Number Threads> Number of threads");                        \
   show("\n  -x <Buffer Size>    Sets the packet size");                     \
   show("\n  -t <TTL>            TTL option");                               \
   show("\n  -z                  Ignore replies");                           \
   show("\n  -D                  Display the packet content (received packets)");\
   show("\n  -v                  Print software version");                   \
   show("\n  --help              Print this screen and exit");               \
   show("\n\n                         <ICMP> Options:");                     \
   show("\n  -Ie                 ICMP packet Echo Request (Ping)");          \
   show("\n  -IE                 ICMP packet Echo Reply");                   \
   show("\n  -Id                 ICMP packet Information Request");          \
   show("\n  -It                 ICMP packet Time Request");                 \
   show("\n  -Iq                 ICMP packet Source Quench");                \
   show("\n  -Im                 ICMP packet Mask Request");                 \
   show("\n  -M <Mask>           ICMP packet Mask Reply (Eg: -M 255.255.0.0)");\
   show("\n  -lI                 ICMP listem mode");                         \
   show("\n\n                         <TCP> Options:");                      \
   show("\n  -Tc                 TCP simple connection");                    \
   show("\n  -Ts                 TCP SYN packet");                           \
   show("\n  -Ta                 TCP ACK packet");                           \
   show("\n  -Tf                 TCP FIN packet");                           \
   show("\n  -Tr                 TCP RST packet");                           \
   show("\n  -Tp                 TCP PSH packet");                           \
   show("\n  -Tx                 XMAS (TCP flags FIN-PSH-URG on)");          \
   show("\n  -Tn                 NULL (All TCP flags off)");                 \
   show("\n  -lT <-P Port>       TCP listen mode (for TCP packets)");        \
   show("\n  -lC <-P Port>       TCP listen connections");                   \
   show("\n\n                         <UDP> Options:");                      \
   show("\n  -u                  UDP mode (UDP Packet)");                    \
   show("\n  -lU <-P Port>       UDP listen mode");                          \
   show("\n\n                         <ARP/RARP> Options:");                 \
   show("\n  -H <MAC Address>    Destination MAC (Eg: -H xx:xx:xx:xx:xx:xx)");\
   show("\n  -h <MAC Address>    Source MAC (Use: -h xx:xx:xx:xx:xx:xx)");   \
   show("\n  -R                  RARP mode (Default is ARP)");               \
   show("\n  -A                  Arp/Rarp REQUEST (Default is REPLY)");      \
   show("\n  -a <IP Address>     Arp'ing: Ping with ARP packets");          \
   show("\n  -f <Number Packets> Mac Flooding: Massive flood with ARP packets (CAUTION)");\
   show("\n  -r <IP-IP>          ARP Cannon: Send ARP packets on a given range IP address");\
   show("\n  -e <IP Address>     Exception IP: Excludes the \"IP Address\" from ARP Cannon");\
   show("\n  -lA                 ARP/RARP listen mode");                     \
   show("\n\n                         <WEB Stress Test> Options:");          \
   show("\n  -U                  UDP attack");                               \
   show("\n  -C                  TCP attack");                               \
   show("\n  -W                  HTTP attack");                              \
   show("\n  -B                  ICMP attack");                              \
   show("\n  -S                  TCP SYN attack");                           \
   show("\n  -K                  TCP ACK attack");                           \
   show("\n  -Y                  SLOWLORIS based attack");                   \
   show("\n  [INFO] Use the -p <port> to set other port than 80 (Default 80)");\
   show("\n\n                          <RSOI - HIVE MIND> Options:");        \
   show("\n  -N <IRC Network>    IRC server to connect");                    \
   show("\n  -L <Channel>        IRC server's channel (Use without \"#\" character)");\
   show("\n  -G <Password>       Channel's password (optional)\n\n");        \
   } while(0)



/* The constructor and destructor has one important layer under the main routine.
   So, i need of a heap's piece for suply the __init__ args from user without 
   have a lot of naked muck flying on modules.
*/

static void __new( void ) {
   __born();
   __pool      = 0;
#if defined(__BSD_SYSTEM__)
   __session   = NULL;
#endif
   pkt         = (struct __input__ *) calloc(1, sizeof(struct __input__));
   _assert(pkt);
}

static void __exit( void ) {
   __cleaning();
#if defined(__BSD_SYSTEM__)
   if (__session) pcap_close(__session);
#endif
   if (pkt) free(pkt);
}


/*   The tail of execution. 
Don't care about the signals on the internal routines. */
static bool __doExec( void *init __obsolet__ ) {

   volatile bool __exec = false;
   const char *arg __unused__ = "__RUN__";

   {
      typeof(const char *) watchdog = __doConsistency();
      if (hardfalse(watchdog)) {
         traceback("Watchdog..");
         log("%s\n", watchdog);
         return __exec;
      }
   }

   if ((pkt->__type__ & __ICMP_MODE__) || (pkt->listenMode & LISTEN_ICMP)) {
      __exec = icmp(&arg);
      goto __END;
   }

   if ((pkt->__type__ & __TCP_MODE__) || 
      ((pkt->listenMode & LISTEN_TCP) || (pkt->listenMode & LISTEN_TCP_CON))){
      __exec = tcp(&arg);
      goto __END;
   }

   if ( (pkt->__type__ & __UDP_MODE__) || (pkt->listenMode & LISTEN_UDP) ) {
      __exec = udp(&arg);
      goto __END;
   }

   if ( (pkt->__type__ & __ARP_MODE__) || (pkt->listenMode & LISTEN_ARP) ) {
      __exec = arp(&arg);
      goto __END;
   }

   if (pkt->__type__ & __WEB_MODE__) {
      __exec = web(&arg);
      goto __END;
   }

   if (pkt->__type__ & __IRC_MODE__) __exec = irc(&arg);

   __END:
   return __exec;
}


/* The infamous main symbol. */
#define today NULL
int main( int argc, char **argv ) {

#if defined(__BSD_SYSTEM__) && (defined(__NetBSD__) || defined(__OpenBSD__))
   show("System not supported.\n");
   show("Avaiable systems are: Linux(all), FreeBSD, MAC OSX or Apple IOS* System.\n\n");
   sho("Exiting..\n");
   return ERR;
#endif

   _START:
   if (argc < 2) {
      __spawn(*argv);
      show("\nDo you need more help or examples ??\n");
      show("   -> Type: 'man nsoq' on terminal.\n");
      show("   -> Look: /usr/share/doc/nsoq/nsoq.txt\n\n");
      return ERR;
   }

   const char *month = __getmonth(today);

   log("\n\t\tStarting Nsoq %s at [%02d.%s.%02d - %02d:%02d:%02d]\n",VERSION,
   _t->tm_mday,month,_t->tm_year+1900,_t->tm_hour,_t->tm_min,_t->tm_sec);

   log("\t\t\tNsoq Project <www.hexcodes.org>\n\n");
   srand(time(NULL));

   register unsigned opt, input, i = 0;
   static char options[] = "UCWBSKYbcDd:p:P:q:s:n:-:F:zt:i:I:M:T:ux:l:vH:h:Aa:f:N:L:G:Rr:e:";

   while((opt = getopt(argc,argv,options)) != -1)
      switch(opt) {
         case 'd':
            snprintf(pkt->dst, sizeof(pkt->dst)-1, "%s", optarg);
            break;
         case 's':
            snprintf(pkt->src, sizeof(pkt->src)-1, "%s", optarg);
            break;
         case 'p':
            pkt->port = (uint16) atoi(optarg);
            break;
         case 'P':
            pkt->srcport = (uint16) atoi(optarg);
            break;
         case 'q':
            pkt->counter = (uint32) atoi(optarg);
            break;
         case 'c': 
            pkt->continuous |= 1;
            break; 
         case 'F':
            pkt->flood = (uint64) atoll(optarg);
            break;
         case 'b':
            pkt->superFlood |= 1;
            break;
         case 'n':
            pkt->numThreads = (uint8) atoi(optarg);
            break;
         case 't':
            pkt->ttl = (uint16) atoi(optarg);
            break;
         case 'z':
            pkt->ignoreReplies |= 1;
            break;
         case 'x':
            pkt->buffsize = (uint64) atoll(optarg);
            break;
         case 'D':
            pkt->packetDisplay |= 1;
            break;
         case 'v':
            __info();
            return 0;
         case '-':
            if (compare("help",optarg)) {
               argc = false;
               goto _START;
            }
            log("Incorrect --%s argument\n", optarg);
            return ERR;

         // Listen Modes
         case 'l':
            if (compare(optarg, "T")) pkt->listenMode |= LISTEN_TCP;
            else if (compare(optarg, "C")) pkt->listenMode |= LISTEN_TCP_CON;
            else if (compare(optarg, "U")) pkt->listenMode |= LISTEN_UDP;
            else if (compare(optarg, "A")) pkt->listenMode |= LISTEN_ARP;
            else if (compare(optarg, "I")) pkt->listenMode |= LISTEN_ICMP;
            else {
               log("Invalid Listem mode (%s).\n", optarg);
               return ERR;
            }
            _assert(pkt->listenMode);
            break;

         // ICMP Stuff
         case 'I':
            pkt->__type__ |= __ICMP_MODE__;
            if (compare(optarg, "t")) pkt->icmpType |= ICMP_TIME_REQ;
            else if (compare(optarg, "d")) pkt->icmpType |= ICMP_INFO;
            else if (compare(optarg, "e")) pkt->icmpType |= ICMP_ECHO_REQ;
            else if (compare(optarg, "E")) pkt->icmpType |= ICMP_ECHO_REPLY;
            else if (compare(optarg, "m")) pkt->icmpType |= ICMP_MASK_REQ;
            else if (compare(optarg, "q")) pkt->icmpType |= ICMP_SRC_QUENCH;
            else {
               log("Invalid ICMP option.\n");   
               return ERR;
            }
            _assert(pkt->icmpType);
            break;
         case 'M':
            pkt->__type__ |= __ICMP_MODE__;
            pkt->icmpType |= ICMP_MASK_REPLY;
            snprintf(pkt->icmpMask, sizeof(pkt->icmpMask)-1, "%s", optarg);
            break;

         // TCP Stuff
         case 'T':
            pkt->__type__ |= __TCP_MODE__;
            if (compare(optarg, "c")) pkt->tcpType |= TCP_CON;
            else if (compare(optarg, "s")) pkt->tcpType |= TCP_SYN;
            else if (compare(optarg, "a")) pkt->tcpType |= TCP_ACK;
            else if (compare(optarg, "r")) pkt->tcpType |= TCP_RST;
            else if (compare(optarg, "f")) pkt->tcpType |= TCP_FIN;
            else if (compare(optarg, "p")) pkt->tcpType |= TCP_PSH;
            else if (compare(optarg, "n")) pkt->tcpType |= TCP_NULL;
            else if (compare(optarg, "x")) {
               pkt->tcpType |= TCP_FIN;
               pkt->tcpType |= TCP_PSH;
               pkt->tcpType |= TCP_URG;
            } else {
               log("Invalid TCP option\n");
               return ERR;
            }

            _assert(pkt->tcpType);
            break;

         // UDP Stuff
         case 'u':
            pkt->__type__ |= __UDP_MODE__;
            break;

         // RARP Stuff
         case 'R':
            pkt->__type__ |= __ARP_MODE__;
            pkt->arpType |= 1; // RARP flag on
            break;

         // ARP Stuff
         case 'h':
            pkt->__type__ |= __ARP_MODE__;
            /* Over input to check sanity */
            input = sscanf(optarg, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
            &pkt->macsrc[0],&pkt->macsrc[1],&pkt->macsrc[2],&pkt->macsrc[3],
            &pkt->macsrc[4],&pkt->macsrc[5],&pkt->macsrc[6],&pkt->macsrc[7],
            &pkt->macsrc[8],&pkt->macsrc[9],&pkt->macsrc[10],&pkt->macsrc[11],
            &pkt->macsrc[12],&pkt->macsrc[13],&pkt->macsrc[14],&pkt->macsrc[15]);
            if (input != 12) {
               log("Invalid source MAC ADDRESS.\n");
               return ERR;
            }
            snprintf(pkt->macsrc, ETH_LEN, "%s", optarg);
            break;

         case 'H':
            if (!(*pkt->dst)) 
               snprintf(pkt->dst, sizeof(pkt->dst)-1, "%s", __LOOPBACK);
            pkt->__type__ |= __ARP_MODE__;
            /* Over input to check sanity */
            input = sscanf(optarg, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
            &pkt->macdst[0],&pkt->macdst[1],&pkt->macdst[2],&pkt->macdst[3],
            &pkt->macdst[4],&pkt->macdst[5],&pkt->macdst[6],&pkt->macdst[7],
            &pkt->macdst[8],&pkt->macdst[9],&pkt->macdst[10],&pkt->macdst[11],
            &pkt->macdst[12],&pkt->macdst[13],&pkt->macdst[14],&pkt->macdst[15]);
            if (input != 12) {
               log("Invalid destination MAC ADDRESS.\n");
               return ERR;
            }
            snprintf(pkt->macdst, ETH_LEN, "%s", optarg);
            break;

         case 'i':
            snprintf(pkt->interface, sizeof(pkt->interface)-1, 
            "%s", (uchar *) optarg);
            break;
         case 'A':
            pkt->__type__ |= __ARP_MODE__;
            pkt->arpSender |= 1; // Request flag on
            break;
         case 'a':
            pkt->__type__ |= __ARP_MODE__;
            pkt->arpMode |= ARP_PING;
            snprintf(pkt->dst,sizeof(pkt->dst)-1,"%s", optarg);
            break;
         case 'f':
            snprintf(pkt->dst, sizeof(pkt->dst)-1, "%s", __LOOPBACK);
            pkt->__type__ |= __ARP_MODE__;
            pkt->macflood = (uint64) atoll(optarg);
            pkt->arpMode |= ARP_FLOOD;
            break;
         case 'r':
            pkt->__type__ |= __ARP_MODE__;
            pkt->arpMode |= ARP_CANNON;
            while(*optarg) {
               if(*optarg == '-') {
                  snprintf(pkt->dst, IP_LEN, "%s", ++optarg);
                  break;
               }
               pkt->src[i++] = *optarg++;
             }
            break;
         case 'e':
            pkt->__type__ |= __ARP_MODE__;
            pkt->arpMode |= ARP_CANNON;
            snprintf(pkt->magickIp, sizeof(pkt->magickIp)-1, 
            "%s", (uchar *) optarg);
            break;

         // WEB Stress Stuff
         case 'U':
            pkt->__type__ |= __WEB_MODE__;
            pkt->webType |= WEB_UDP;
            break;
         case 'C':
            pkt->__type__ |= __WEB_MODE__;
            pkt->webType |= WEB_TCP;
            break;
         case 'W':
            pkt->__type__ |= __WEB_MODE__;
            pkt->webType |= WEB_HTTP;
            break;
         case 'B':
            pkt->__type__ |= __WEB_MODE__;
            pkt->webType |= WEB_ICMP;
            break;
         case 'S':
            pkt->__type__ |= __WEB_MODE__;
            pkt->webType |= WEB_SYN;
            pkt->tcpType |= TCP_SYN;
            break;
         case 'K':
            pkt->__type__ |= __WEB_MODE__;
            pkt->webType |= WEB_ACK;
            pkt->tcpType |= TCP_ACK;
            pkt->tcpType |= TCP_PSH;
            break;
         case 'Y':
            pkt->__type__ |= __WEB_MODE__;
            pkt->webType |= WEB_SLOW;
            break;

         // IRC Stuff
         case 'N':
            pkt->__type__ |= __IRC_MODE__;
            snprintf(pkt->dst, sizeof(pkt->dst)-1,"%s", optarg);
            break;
         case 'L':
            pkt->__type__ |= __IRC_MODE__;
            snprintf(pkt->ircRoom, sizeof(pkt->ircRoom)-1,"%s", optarg);
            break;
         case 'G':
            pkt->__type__ |= __IRC_MODE__;
            snprintf(pkt->ircPass, sizeof(pkt->ircPass)-1,"%s", optarg);
            break;

         default:
            log("Invalid Option!\n");
            return ERR;
      }

   if (getuid()) {
      log("Require root privileges. \nExiting..\n\n");
      return ERR;
   }

   if (! __doExec("__START_NSOQ_")) { 
      pkt->numThreads = 0x00;
      return ERR;
   }

   pthread_exit(0);
}

