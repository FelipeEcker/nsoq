/*......,,,,,,,.............................................................
*
* @@NAME:     Module Package UTILS
* @@VERSION:  1.0.0
* @@DESC:     UTILS source file (this file is part of MpTcp tool).
* @@AUTHOR:   Felipe Ecker (Khun) <khun@hexcodes.org>
* @@DATE:     10/11/2012 04:30:01
* @@MANIFEST:
*      Copyright (C) Felipe Ecker 2003-2013.
*      You should have received a copy of the GNU General Public License 
*      inside this program. Licensed under GPL 3
*      If not, write to me an e-mail please. Thank you.
*
*...........................................................................
*/

#include "../include/core.h"

/* I'll cacth the SIGALRM and SIGINT for a clear exit.. */
inline void __sigcatch( int __signal__ ) {

   /* Force exit to call __destructor__ */
   exit(ERR);
}


/* Mutex/Socket pool init */
inline void __born( void ) {

   register uint16 it = 0;
   for (; it < SLIMIT; it++) __sockets[it] = -2;

   pthread_mutex_init(&__mutex, NULL);
}


/* Threads/Mutex/SocketPool cleaner */
inline void __cleaning( void ) {

   register uint16 it;
   for (it = 0; it < pkt->numThreads; it++) pthread_kill(__threads[it], SIGINT);
   for (it = 0 ; it < __pool; it++) if (__sockets[it] > -1) close(__sockets[it]);

   pthread_mutex_destroy(&__mutex);
}


/* The asexual GLIBC ether_ntoa doesn't put %02x on itself routine */
__malloc__ inline const char *eth_ntoa( struct eth_addr *__addr ) {

   static char __buff[ETH_LEN];

   snprintf(__buff, ETH_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
      __addr->octet[0], __addr->octet[1],
      __addr->octet[2], __addr->octet[3],
      __addr->octet[4], __addr->octet[5]
   );

   return __buff;
}

/* GLIBC ether_aton_r(). RE-writen here for BSD campatible. 
Sorry dear Stallman :) */
struct eth_addr *eth_aton_r ( const char *asc, struct eth_addr *addr ) {

   register size_t cnt;

   for (cnt = 0; cnt < 6; ++cnt) {
      register unsigned int number;
      char ch;

      ch = _tolower (*asc++);
      if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) return NULL;
      number = isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);
      ch = _tolower (*asc);

      if ((cnt < 5 && ch != ':') || (cnt == 5 && ch != '\0' && !isspace (ch))){
         ++asc;
         if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) return NULL;
         number <<= 4;
         number += isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);
         ch = *asc;
         if (cnt < 5 && ch != ':') return NULL;
      }

      /* Store result.  */
      addr->octet[cnt] = (uchar) number;
      /* Skip ':'.  */
      ++asc;
   }

   return addr;
}


/* Socket handling */
inline signed int __socketPool( const bool raw,
                                      const uint8 type,
                                      const bool stream ) 
{
   __RENEW:
   if (__sockets[__pool] > -1) {
      log("Socket in use.\n\n");
      __pool++;
      goto __RENEW;
   }

   if ( __pool  >= (SLIMIT) ) goto __MISS;

   if (raw) __sockets[__pool] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
   else {
      switch(type) {
         case __ICMP_MODE__: 
            __sockets[__pool] = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            break;

         case __TCP_MODE__:
            if (stream) __sockets[__pool] = socket(AF_INET, SOCK_STREAM, 0);
            else __sockets[__pool] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            break;

         case __UDP_MODE__:
            __sockets[__pool] = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
            break;

#if defined(__LINUX_SYSTEM__)
         case __ARP_MODE__:
         /* __linux__ defines ETH_P_ALL to 0x0003 */
            __sockets[__pool] = socket(PF_PACKET, SOCK_RAW, htons(0x0003));
            break;
#endif
         default: pass;
      }
   }

   __MISS:
   if (__sockets[__pool] < 0) {
      log("Error on socket create. \nNo more avaiable sockets. Restart the MpTcp.\n\n");
      kill(getpid(), SIGALRM); /* Self destruction */
      return 0;
   }

   return __sockets[__pool++];
}


/* Most universal checksum */
inline uint16 __checksum( uint16 *addr, uint32 len ) {

   register int nleft = len;
   register uint16 *w = addr;
   register int sum = 0;
   uint16 answer = 0;

   while (nleft > 1) {
      sum += *w++;
      nleft -= 2;
   }

   if (nleft == 1) {
      *(uchar *) (&answer) = *(uchar *) w;
      sum += answer;
   }

   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   answer = ~sum;

   return answer;
}


/* Threads pool engine */
inline bool __threadPool(   const uint16 numThreads,
                            const void *__callback,
                            void *__args )
{

   register uint16 it = 0;
   do {
      if ( pthread_create(&__threads[it], NULL, __callback, __args) ) {
         log("ERROR on create thread.\n\n");
         return false;
      }
   } while (++it < numThreads);

   return (bool) __threads[it - 1];
}


/* Set broadcast socket handle */
__pure__ void __set_broadcast( const uint32 __socket ) {

   unsigned set = 0x01;
   setsockopt(__socket, SOL_SOCKET, SO_BROADCAST, &set, sizeof(unsigned));
}


/* Set TCP NODELAY socket handle*/
__pure__ inline void __set_nodelay( const uint32 __socket ) {

   unsigned set = 0x01;
   setsockopt(__socket, IPPROTO_TCP, TCP_NODELAY, &set, sizeof(unsigned));
}


/* Set raw constructor sender socket handle */
__pure__ void __set_hdrincl( const uint32 __socket ) {

   unsigned set = 0x01;
   setsockopt(__socket, IPPROTO_IP, IP_HDRINCL, &set, sizeof(unsigned));
}

/* Set socket to NON BLOCKING strem */
__pure__ inline void __set_nonblock( const uint32 __socket ) {

   fcntl(__socket, F_SETFL, O_NONBLOCK);
}


/* Target/Source/Port/Interface lookup handler */
inline bool __lookup( struct sockaddr_in *_sockaddr, 
                      char *address,
                      const uint16 port,
                      const bool isSource ) 
{

   const char *interfaces[] = {
         "eth0","eth1","eth2",
         "em0","em1","em2",
         "en0","en1","en2",
         "wlan0","wlan1","wlan2",
         "lo","lo0","lo1"
   };
   char __ip[INET_ADDRSTRLEN];
   const char **eth = interfaces;
   bool myip = false;
   memset(_sockaddr, 0, sizeof(struct sockaddr_in));

   if (isSource) {
      if ( !(*address) ) {
         if (pkt->listenMode && !(pkt->listenMode & LISTEN_ARP) ) {  
            _sockaddr->sin_addr.s_addr = INADDR_ANY; goto __END; 
         }

         if (*pkt->interface) myip = __fetchIp(pkt->interface, __ip);
         else {
            while (*eth) 
               if ( (myip = __fetchIp(*eth++, __ip)) ) {
                  snprintf(pkt->interface, 16, "%s", *(eth - 1));
                  break;
               }
         }

         if (!myip) {
            log("No valid IP found on any interfaces.\n");
            log("Use -s <host> otpion.\n");
            return false;
         } else address = __ip;

      }

      if ( !(*pkt->interface) && ((pkt->__type__ & __ARP_MODE__) || 
         (pkt->listenMode & LISTEN_ARP) )) {
         while (*eth)
            if ( (myip = __fetchIp(*eth++, __ip)) ) {
               snprintf(pkt->interface, 16, "%s", *(eth - 1));
               break;
            }

         if ( !(*pkt->interface) ) {
            log("No Valid interface found.\nTry use -i <interface>.\n\n");
            return false;
         }
      }
   }

   auto struct hostent *host;
   if (!(host = (struct hostent *) gethostbyname(address))) {
      log("Error on lookup hostname: \"%s\" is an invalid host.\n\n", address);
      return false;
   } else {
      memcpy(&(_sockaddr->sin_addr.s_addr), 
      host->h_addr_list[0], host->h_length);
   }
   __END:
   _sockaddr->sin_family = AF_INET;
   if (port) _sockaddr->sin_port = htons(port);
   else _sockaddr->sin_port = htons(rand() % 0xFFFE);

   return true;
}


/* Give us the sysdate time under the global _t */
inline void __sysdate( void ) {

   time(&_time);
   _t = localtime(&_time);
}


/* Generate a random IP address */
#if !defined(WEAK_GCC)
__hot__ inline const char *__randomIp ( void ) {
#else
inline const char *__randomIp ( void ) {
#endif

   static const char ip[INET_ADDRSTRLEN] __nocommon__;
   struct in_addr addr __nocommon__;
   srand(rand() % 0xFFFFFFFF);

   addr.s_addr = rand() % 0xFFFFFFFE;
   inet_ntop(AF_INET, &(addr), (char *) ip, INET_ADDRSTRLEN);

   return ip;
}


/* Generate a ramdom MAC address */
#if !defined(WEAK_GCC)
__hot__ inline const char *__randomMac ( void ) {
#else
inline const char *__randomMac ( void ) {
#endif

   volatile struct eth_addr eth __nocommon__;
   register uint8 i;
   srand(rand() % 0xFFFFFFFF);

   for (i = 0; i < 6; i++) eth.octet[i] = rand() % 0xFE;
   return eth_ntoa((struct eth_addr *) &eth);
}


/* Give us the interface IP address information */
int __fetchIp( const char *__device , char *__ip) {

   register uint32 sock;
   signed int __ctrl;
   auto struct ifreq eth;

   sock = socket(AF_INET, SOCK_DGRAM, 0);
   eth.ifr_addr.sa_family = AF_INET;
   strncpy(eth.ifr_name, __device, (IFNAMSIZ - 1));
   __ctrl = !ioctl(sock, SIOCGIFADDR, &eth);

   if (__ctrl) {
      auto struct sockaddr_in *address = (struct sockaddr_in *) &eth.ifr_addr;
      inet_ntop(AF_INET, &(address->sin_addr), __ip, INET_ADDRSTRLEN);
   }
   
   return !!__ctrl;
}


/* Give us the interface MAC address */
__malloc__ inline const char *__fetchMac( const char *__device ) {

#if defined(__LINUX_SYSTEM__)
   register uint32 sock, i = 0, j = 0;
   auto struct ifreq eth;
   static char mac[ETH_LEN];

   sock = socket(AF_INET, SOCK_DGRAM, 0);
   strncpy(eth.ifr_name, __device, (IFNAMSIZ - 1));
   ioctl(sock, SIOCGIFHWADDR, &eth);
   close(sock);

   for (; i < 6; i++)
      j += snprintf(mac + j, sizeof(mac) - j, "%02X:", 
      (uchar) eth.ifr_hwaddr.sa_data[i]);

   return mac;

#else
   auto struct ifaddrs *ifaddrs_ptr;
   auto struct ifaddrs *ifa_next;
   auto struct sockaddr_dl *sdl;
   const char *mac_address;
   static char mac[ETH_LEN];

   getifaddrs (&ifaddrs_ptr);
   while(true) {
      if ( (ifaddrs_ptr->ifa_addr->sa_family == AF_LINK) && 
      (compare(ifaddrs_ptr->ifa_name,__device)) ) {
         sdl = (struct sockaddr_dl *) ifaddrs_ptr->ifa_addr;
         if (sdl->sdl_type == IFT_ETHER) {
            mac_address = LLADDR(sdl);
            snprintf(mac, ETH_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
            (uchar)mac_address[0],(uchar)mac_address[1],(uchar)mac_address[2],
            (uchar)mac_address[3],(uchar)mac_address[4],(uchar)mac_address[5]);
            return mac;
         }
      }

      ifa_next= ifaddrs_ptr->ifa_next;

      if (!ifa_next) {
         freeifaddrs (ifaddrs_ptr);
         return NULL;
      }

      ifaddrs_ptr= ifa_next;
   }

#endif
}


/* Check the BPF device os BSD family */

__pure__ inline bool __checkBPF( const char *device ) {

#if defined(__BSD_SYSTEM__)
   signed int __bpf = 0, buff_len = 1;
   char buff[12] = { 0 };
   uint8 it = 0;

   for(; it < 99; it++) {
      snprintf(buff, sizeof(buff)-1, "/dev/bpf%d", it );
      if ( (__bpf = open(buff, O_RDWR)) != -1) break;
   }

   if (__bpf == -1) return false;

   struct ifreq bound_if;
   strlcpy(bound_if.ifr_name, device, IFNAMSIZ);

   if ((ioctl(__bpf, BIOCSETIF, &bound_if ) > 0) ||
      (ioctl(__bpf, BIOCIMMEDIATE, &buff_len) == -1) ||
      (ioctl(__bpf, BIOCGHDRCMPLT, &buff_len ) == -1) ||
      (ioctl(__bpf, BIOCGBLEN, &buff_len ) == -1) )
         return false;

   return __bpf;
#endif

   return true;
}


/* Give us the packet content */
__pure__ inline void __show_packet( const uchar *__buff, 
                                    const uint16 __size ) 
{

   register uint32 it = 0;
   register uchar *hexa = (uchar *) calloc(1, 41); 
   register uchar *asc = (uchar *) calloc(1, 17);
   register uchar *__hexa = hexa, *__asc = asc;
   const uchar line_blank[] =   
   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";

   #define __VALID_ASCII( value ) \
        (__buff[it + value] >= 0x21) && (__buff[it + value] < 0x7F)
   #define lined(...) snprintf(__VA_ARGS__)
   #define DIV "\t.........................................................................\n"

   //show(DIV);
   show("\n");
   for ( ;; it += 2 ) {

      if ( it && !(it % 16) ) show("\tbytes %02d-%02d:\t%s %s\n", 
      (it-16), (it-1), hexa = __hexa, asc= __asc);

      if (it >= __size) {
         if(it % 16) {
            lined((char *) hexa, 41 - (((it % 16) / 2) * 5), "%s",line_blank);
            show("\tbytes %02d-%02d:\t%s %s\n", 
            (it - (it % 16)), (it-1), __hexa, __asc);
         }
         break;
      }

      lined((char *) hexa, 3, "%02x", __buff[it]);
      (__VALID_ASCII(0)) ? 
         lined((char *) asc, 2, "%c", __buff[it]) : 
         lined((char *) asc, 2, "%c", 0x2E);
      lined((char *) (hexa + 2), 4,"%02x ", __buff[it + 1]);
      (__VALID_ASCII(1)) ? 
         lined((char *) (asc + 1), 3, "%c", __buff[it + 1]) : 
         lined((char *) (asc + 1), 2, "%c", 0x2E);

      hexa += 5; asc += 2;
   }

   free(__hexa);
   free(__asc);
   show("\n\n");
}


/* The famous getch( ). Customizable under termios API */
inline unsigned __getch( void ) {

   static struct termios old,new;
   unsigned ch;

   tcgetattr(STDIN_FILENO,&old);
   new = old;
   new.c_lflag &= ~(ICANON | ECHO);
   tcsetattr(STDIN_FILENO,TCSANOW,&new);
   ch = getchar();
   tcsetattr(STDIN_FILENO,TCSANOW,&old);

   return ch;
}


/* Simple month information return */
__malloc__ inline const char *__getmonth( const char *_sysdate __obsolet__) {

   __sysdate();
   switch(_t->tm_mon) {
      case -0xffff ... -1: return "__sysdate__"; /* Back compatible :) */
      case 0: return "Jan";
      case 1: return "Feb";
      case 2: return "Mar";
      case 3: return "Apr";
      case 4: return "May";
      case 5: return "Jun";
      case 6: return "Jul";
      case 7: return "Aug";
      case 8: return "Sep";
      case 9: return "Oct";
      case 10: return "Nov";
      case 11: return "Dec";
      case 12 ... 0xffff: return "__sysdate__"; /* Same case above */
   }

   return NULL;
}

