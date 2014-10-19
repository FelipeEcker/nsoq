/*......,,,,,,,.............................................................
*
* @@NAME:     Module CONSISTENCY
* @@VERSION:  1.0.1
* @@DESC:     Consistency source file (this file is part of Nsoq tool).
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

/* Too many sanity checks and default values */
const char *__doConsistency( void ) {

   const uint16 DEFAULT_WEBSTRESS_PORT   = 0x50;    /* Decimal 80   */
   const uint16 DEFAULT_IRC_PORT = 0x1A0B;          /* Decimal 6667 */
   const uint8 DEFAULT_TTL = 0x20 + (rand() % 0xDF);
   const char *DEFAULT_IRC_ROOM = "nsoq";
   const char *DEFAULT_IRC_PASS = "nsoqpass";

   uint8 __doCheck;

   __doCheck = 0x01;
   if (pkt->listenMode & LISTEN_TCP) __doCheck <<= 0x1;
   if (pkt->listenMode & LISTEN_TCP_CON) __doCheck <<= 0x1;
   if (pkt->listenMode & LISTEN_UDP) __doCheck <<= 0x1;
   if (pkt->listenMode & LISTEN_ICMP) __doCheck <<= 0x1;
   if (pkt->listenMode & LISTEN_ARP) __doCheck <<= 0x1;
   if (__doCheck > 0x02) return "Invalid listen option: Use one listen mode at once.";

   if ( ((pkt->listenMode & LISTEN_TCP) || 
         (pkt->listenMode & LISTEN_TCP_CON) || 
         (pkt->listenMode & LISTEN_UDP)) 
      && !pkt->srcport)
      return "Invalid listen option: The listen TCP/UDP modes needs set -P <source_port> option.";

   if (pkt->listenMode && pkt->__type__)
      return "Invalid listen option: Use listen mode without other control flags.";

   if (pkt->numThreads && pkt->listenMode) {
      return "Invalid listen option: Don't use threads with listen modes.";
   }

   if (pkt->numThreads && (pkt->__type__ & __IRC_MODE__)) {
      return "Invalid option: Don't use threads on IRC mode (RSOI handler).";
   }

   if ((pkt->continuous && (pkt->flood || pkt->superFlood)) ||
      (pkt->flood && (pkt->superFlood || pkt->continuous)) ||
      (pkt->superFlood && (pkt->continuous || pkt->flood)) )
      return "Invalid options: Use (Continuous, Flood or SuperFlood) option separatelly.";

   if ( (pkt->port || pkt->srcport) && (
      (pkt->__type__ & __ICMP_MODE__) ||
      (pkt->__type__ & __ARP_MODE__) ||
      (pkt->listenMode & LISTEN_ARP) ||
      (pkt->listenMode & LISTEN_ICMP)) )
      return "Invalid options: Use -p <port> or -P <srcport> options only for TCP/UDP packets or WebStress/IRC modes.";

   __doCheck = 0x01;
   if (pkt->__type__ & __ICMP_MODE__) __doCheck <<= 0x1;
   if (pkt->__type__ & __TCP_MODE__) __doCheck <<= 0x1;
   if (pkt->__type__ & __UDP_MODE__) __doCheck <<= 0x1;
   if (pkt->__type__ & __ARP_MODE__) __doCheck <<= 0x1;
   if (pkt->__type__ & __WEB_MODE__) __doCheck <<= 0x1;
   if (pkt->__type__ & __IRC_MODE__) __doCheck <<= 0x1;
   if (__doCheck > 0x02) return "Invalid options: Use (ICMP, TCP, UDP, ARP, WEBSTRESS and IRC) modes separatelly.";

    __doCheck = 0x01;
   if (pkt->webType & WEB_ICMP) __doCheck <<= 0x1;
   if (pkt->webType & WEB_TCP) __doCheck <<= 0x1;
   if (pkt->webType & WEB_UDP) __doCheck <<= 0x1;
   if (pkt->webType & WEB_HTTP) __doCheck <<= 0x1;
   if (pkt->webType & WEB_SYN) __doCheck <<= 0x1;
   if (pkt->webType & WEB_ACK) __doCheck <<= 0x1;
   if (pkt->webType & WEB_SLOW) __doCheck <<= 0x1;
   if (__doCheck > 0x02) return "Invalid options: Use each WEBSTRESS mode option separatelly.";

   if ( (pkt->tcpType & TCP_CON) && (pkt->flood || pkt->superFlood) )
      return "Invalid options: Use TCP Connection without flood modes.";

   if ( ((pkt->__type__ & __TCP_MODE__) || (pkt->__type__ & __UDP_MODE__)) && 
   !pkt->port)
      return "Invalid options: TCP/UDP packets needs set option -p <port>.";

   if (pkt->buffsize % 2)
      return "Invalid options: The buffer size option needs be an even number.";

   if ( (pkt->__type__ & __ARP_MODE__) && !(*pkt->macdst) &&
         (!(pkt->arpMode & ARP_PING) &&
         !(pkt->arpMode & ARP_FLOOD)   &&
         !(pkt->arpMode & ARP_CANNON))
      )
         return "Invalid options: ARP packets needs to set \"-H <destination MAC>\" option.";

   if ( (pkt->__type__ & __WEB_MODE__) && !pkt->port) 
      pkt->port = DEFAULT_WEBSTRESS_PORT;
   if ( (pkt->__type__ & __IRC_MODE__) && !pkt->port) 
      pkt->port = DEFAULT_IRC_PORT;

   if (!pkt->ttl) pkt->ttl = DEFAULT_TTL;
   else
      if (pkt->__type__ & __ARP_MODE__) 
         return "Invalid options: ARP packets don't need set TTL information.";
      else pass;

   {
      uint8 it;
      for (it=0; it < 17; it++)
         if ( (tolower(pkt->macsrc[it]) > 'f') || 
         ((tolower(pkt->macdst[it]) > 'f')) )
            return "Error on MAC address: Characters invalid.";
   }

   if (pkt->numThreads > TLIMIT)
      return "Invalid options: The threads number needs be less of ~1000";

   if (pkt->__type__ & __IRC_MODE__) {
      if (!(*pkt->ircRoom)) snprintf(pkt->ircRoom, 6, "%s", DEFAULT_IRC_ROOM);
      if (!(*pkt->ircRoom)) snprintf(pkt->ircPass, 7, "%s", DEFAULT_IRC_PASS);
   }

   return NULL;
}

