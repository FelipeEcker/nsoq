/*......,,,,,,,.............................................................
*
* @@NAME:     CORE.H
* @@VERSION:  1.9.4
* @@DESC:     Include file (this file is part of Nsoq tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     18/10/2014 (16:30:00)
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2014.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/


#ifndef CORE_H
#define CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <termios.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(__FreeBSD__) || \
defined(__OpenBSD__)     || \
defined(__NetBSD__)      || \
defined(__DARWIN_ONLY_UNIX_CONFORMANCE)
   #include <ifaddrs.h>
   #include <net/bpf.h>
   #include <pcap.h>
   #include <sys/uio.h>
   #include <netinet/in_systm.h>
   #include <net/if.h>
   #include <net/if_dl.h>
   #include <net/if_types.h>
   #include <netinet/ip.h>
   #include <netinet/ip_icmp.h>
   #include <netinet/tcp.h>
   #include <netinet/udp.h>
   #define __BSD_SYSTEM__
   #if defined(__NetBSD__) || defined(__OpenBSD__)
      #warning System not supported. Avaiable systems are: \
      Linux(all), FreeBSD, MAC OSX and MAC IOS* Systems. Exiting..
   #endif

#elif defined(linux) || defined(__linux) || defined(__linux__)
   #include <netinet/ip.h>
   #include <netinet/ip_icmp.h>
   #include <netinet/tcp.h>
   #include <netinet/udp.h>
   #include <linux/if.h>
   #include <linux/if_packet.h>
   #define __LINUX_SYSTEM__

#else
   #error System not supported. Avaiable systems are: \
   Linux(all), FreeBSD, MAC OSX and MAC IOS* Systems. Exiting..
#endif

#if defined(__GNUC__)
   #if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 4)
      #define WEAK_GCC
   #endif
#endif

#define uchar           unsigned char
#define uint8           u_int8_t
#define uint16          u_int16_t
#define uint32          u_int32_t
#define uint64          u_int64_t

#ifdef true
   #undef true
#endif
#ifdef false
   #undef false
#endif
#define true            1
#define false           0
#define ERR             false
#define TLIMIT          1000
#define SLIMIT          TLIMIT * 3

#define SIZE_IP         0x14   /* sizeof(struct iphdr)    - 20 bytes   */
#define SIZE_ICMP       0x08   /* sizeof(struct icmphdr)  - 08 bytes   */
#define SIZE_UDP        0x08   /* sizeof(struct udphdr)   - 08 bytes   */
#define SIZE_TCP        0x14   /* sizeof(struct tcphdr)   - 20 bytes   */
#define SIZE_AUX        0x0C   /* size of auxtcp header   - 12 bytes   */
#define SIZE_ETH        0x0E   /* size of ether_header    - 14 bytes   */

#define __WEB_MODE__    0x01
#define __ICMP_MODE__   0x02
#define __UDP_MODE__    0x04
#define __TCP_MODE__    0x08
#define __ARP_MODE__    0x10
#define __IRC_MODE__    0x20

#define ETH_ARP         0x0806
#define ETH_RARP        0x8035
#define ETH_ARPREQ      0x0001
#define ETH_ARPREPLY    0x0002
#define ETH_RARPREQ     0x0003
#define ETH_RARPREPLY   0x0004
#define ETH_LEN         0x12
#define IP_LEN          0x10

#define TCP_FIN         0x00000001
#define TCP_SYN         0x00000002
#define TCP_RST         0x00000004
#define TCP_PSH         0x00000008
#define TCP_ACK         0x00000010
#define TCP_URG         0x00000020
#define TCP_NULL        0x00000040
#define TCP_CON         0x00000080
#define ICMP_INFO       0x00000100
#define ICMP_TIME_REQ   0x00000200
#define ICMP_ECHO_REQ   0x00000400
#define ICMP_ECHO_REPLY 0x00000800
#define ICMP_MASK_REQ   0x00001000
#define ICMP_MASK_REPLY 0x00002000
#define ICMP_SRC_QUENCH 0x00004000
#define ARP_PING        0x00008000
#define ARP_FLOOD       0x00010000
#define ARP_CANNON      0x00020000
#define WEB_UDP         0x00040000
#define WEB_TCP         0x00080000
#define WEB_HTTP        0x00100000
#define WEB_ICMP        0x00200000
#define WEB_SYN         0x00400000
#define WEB_ACK         0x00800000
#define WEB_SLOW        0x20000000
#define LISTEN_ICMP     0x01000000
#define LISTEN_TCP      0x02000000
#define LISTEN_TCP_CON  0x04000000
#define LISTEN_UDP      0x08000000
#define LISTEN_ARP      0x10000000


#if defined(bool)
   #undef bool
#endif

#if defined(getch)
   #undef getch
#endif

#define hardtrue( a )   __builtin_expect(!!(a), true)
#define hardfalse( a )  __builtin_expect(!!(a), false)
#define __cache( a )    __builtin_prefetch(a)

#define __constructor__ __attribute__((constructor))
#define __destructor__  __attribute__((destructor))
#define __unused__      __attribute__((unused))
#define __nocommon__    __attribute__((nocommon))
#define __obsolet__     __attribute__((deprecated))
#define __noreturn__    __attribute__((noreturn))
#define __packed__      __attribute__((packed))
#define __malloc__      __attribute__((malloc))

#if !defined(WEAK_GCC)
   #define __call__     __attribute__((hot))
#else
   #define __call__		__attribute__((used))
#endif

#undef show 
#undef log 
#undef pass
#define show(...)       fprintf(stdout, __VA_ARGS__)
#define log(...)        fprintf(stderr, __VA_ARGS__)
#define pass            __asm__ volatile("nop")
#define __LOOPBACK      "127.0.0.1"

#define compare(x,y) (!strcmp(x,y) ? true : false)

#if defined(DEBUG)
#define traceback(msg)   log("%s (Breakpoint on %s: Line %d)\n", msg, __FILE__, __LINE__)
#else
#define traceback(msg)   __asm__ __volatile__("nop")
#endif

#if defined(_quit)
#undef _quit
#endif
#define _quit( msg )     exit(log("%s (Core traceback: Line %d)\n\n", msg, __LINE__))
#define _assert( expr )  (expr) ? true : _quit("Assertion Error")

#if defined(__PACKET__)
   #undef __PACKET__
#endif


struct eth_addr {
   uint8 octet[6];
} __packed__;
#define ethaddr          struct eth_addr

typedef int bool;
time_t _time;
struct tm *_t;
pthread_t __threads[TLIMIT];
pthread_mutex_t __mutex;
signed int __sockets[SLIMIT];
uint32 __pool;
char addressbuff[sizeof(struct sockaddr_in)*2];

#if defined(__BSD_SYSTEM__)
pcap_t *__session;
#endif

struct __socks {
   int sock;
   bool up;
} __packed__;

struct __data {
   struct sockaddr_in *source;
   struct sockaddr_in *target;
} __packed__;

#define __PACKET__
struct __input__ {
   uint8 __type__;          /* Packet type               */
   uint32 icmpType;         /* ICMP packet type          */
   uint32 tcpType;          /* TCP packet type           */
   uint32 webType;          /* WEB Stress packet type    */
   uint32 ircType;          /* IRC type option           */
   uint32 listenMode;       /* Listen modes              */
   uint32 arpMode;          /* Arp mode handler          */
   uint64 flood;            /* Time flood                */
   uint64 buffsize;         /* Packet buffer size        */
   char src[256];           /* Source address            */
   char dst[256];           /* Destination address       */
   char macsrc[ETH_LEN];    /* Source Mac addres         */
   char macdst[ETH_LEN];    /* Destination Mac address   */
   char interface[16];      /* Interface name            */
   char magickIp[IP_LEN];   /* Off IP from Arp Cannon    */
   char ircRoom[64];        /* IRC room name             */
   char ircPass[64];        /* IRC room password         */
   char icmpMask[IP_LEN];   /* ICMP mask                 */
   uint16 port;             /* TCP/UDP port              */
   uint16 srcport;          /* TCP/UDP source port       */
   uint16 numThreads;       /* Threads Number            */
   uint32 counter;          /* Number packtes to send    */
   uint64 macflood;         /* Mac flood number packets  */
   uint8 ttl;               /* Connection ttl         */
   uint8 arpType:1;         /* Arp/Rarp packet type [0=ARP / 1=RARP]        */
   uint8 arpSender:1;       /* Arp packet sender type [0=Reply / 1=Request\ */
#if defined(__BSD_SYSTEM__)
   signed int bpf;          /* BSD bpf device            */
#endif
   uint8 continuous:1;      /* Continue flag             */
   uint8 superFlood:1;      /* Super flood flag          */
   uint8 ignoreReplies:1;   /* Ignore reply flag         */
   uint8 packetDisplay:1;   /* Show packet content       */

} __packed__ *pkt;


/* Exported global symbols */
void            __sigcatch(int);
const char      *eth_ntoa(struct eth_addr *);
struct eth_addr *eth_aton_r(const char *, struct eth_addr *);
void            __born(void);
void            __cleaning(void );
signed int      __socketPool(const bool, const uint8, const bool);
uint16          __checksum(uint16 *, const uint32);
bool            __threadPool(const uint16, const void *, void *);
void            __set_broadcast(const uint32);
void            __set_nodelay(const uint32);
void            __set_hdrincl(const uint32);
void            __set_nonblock(const uint32);
void            __set_keepalive(const uint32);
bool            __lookup(struct sockaddr_in *,char *,const uint16,const bool);
void            __sysdate(void);
unsigned        __getch(void);
const char     *__randomIp(void);
const char     *__randomMac(void);
int             __fetchIp(const char *, char *);
const char     *__fetchMac(const char *);
bool            __checkBPF(const char *);
void            __show_packet(const uchar *, const uint16);
const char     *__getmonth(const char *);

#endif /* CORE_H */

