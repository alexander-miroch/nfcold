/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct udphdr
{ 
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};
/*****************************************************************************
* Copyright (C) 2000 Nik Weidenbacher
* nikw@martnet.com
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*****************************************************************************/


struct flow_ver5_hdr {
	uint16_t version;
	uint16_t count;
	uint32_t uptime;
	uint32_t unix_secs;
	uint32_t unix_nsecs;
	uint32_t flow_sequence;
	uint8_t  engine_type;
	uint8_t  engine_id;
	};
struct flow_ver5_rec {
	uint32_t srcaddr;
	uint32_t dstaddr;
	uint32_t nexthop;
	uint16_t input_index;
	uint16_t output_index;
	uint32_t dPkts;
	uint32_t dOctets;
	uint32_t First;
	uint32_t Last;
	uint16_t srcport;
	uint16_t dstport;
	uint8_t unused2;
	uint8_t tcp_flags;
	uint8_t prot;
	uint8_t tos;
	uint16_t src_as;
	uint16_t dst_as;
	uint8_t dst_mask;
	uint8_t src_mask;
	ushort pad2;
	};

struct sdata {
        uint32_t start,end;
        uint32_t bid;
};

#define MAXNFTYPES 30
