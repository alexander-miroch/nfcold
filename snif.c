#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include "proto.h"


void usage(int ret) {
        FILE *stream = (ret) ? stderr : stdout;

        fprintf(stream, "Usage: snif [ -i ip ] [ -p port ]  \n");
        exit(ret);
}

void process(u_char *, const struct pcap_pkthdr *, const u_char *);
void send_piece(uint32_t, uint32_t, uint32_t);

unsigned short port = 9998;
char *dev 	    = "eth0";
char filter[256 * MAXNFTYPES + 256];

struct sfp_t {
	struct flow_ver5_hdr nf;
	unsigned short port;
	uint32_t start;
};

struct sfp_t sfp[MAXNFTYPES];

struct flow_ver5_hdr savedfp[MAXNFTYPES];


//inline struct flow_ver5_hdr *getNf(uint8_t type, uint8_t eid, unsigned short port) {
inline struct sfp_t *getNf(uint8_t type, uint8_t eid, unsigned short port) {
	int i=0;
	for (; i<MAXNFTYPES; ++i) {
		if (!sfp[i].nf.version)
			break;

		if (sfp[i].nf.engine_id == eid &&
			sfp[i].nf.engine_type == type &&
			sfp[i].port == port)
			return &sfp[i];
	}

	sfp[i].nf.version = 5;
	sfp[i].nf.engine_type = type;
	sfp[i].nf.engine_id = eid;
	sfp[i].port = port;

	return &sfp[i];

}
int debug = 0;
int sk;

int make_connection(void);

int main(int argc, char *argv[]) {
	char c;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *snif;
	struct bpf_program fp;
	bpf_u_int32 mask;	
	bpf_u_int32 net;	
	int i =0;
	int x = 0;
	int cnt = 0;
	unsigned short ports[MAXNFTYPES];
	char portbuf[MAXNFTYPES * 256];
	int len,wr;

	bzero(ports, MAXNFTYPES * sizeof(unsigned short));
	while ((c = getopt(argc, argv, "i:p:dx")) != -1) {
                switch (c) {
                        case 'i':
				dev = strdup(optarg);
                                break;
			case 'p':
				if (cnt == MAXNFTYPES - 1) {
					fprintf(stderr, "Too many ports");
					exit(1);
				}
				ports[cnt++] = atoi(optarg);	
				break;	
			case 'd':
				debug = 1;
				break;	
			case 'x':
				x=1;
				break;
                        case '?':
                                break;
                        default:
                                usage(1);
                }
        }

	openlog("nfcheck", LOG_NDELAY, LOG_LOCAL1);
	if (daemon(0, 0) < 0) {
		fprintf(stderr, "daemonize error");
		exit (1);
	}

	//setvbuf(stdout, 0, _IONBF, 0);
	for (; i<MAXNFTYPES; i++) {
		sfp[i].nf.version = 0;
		sfp[i].start = 0;
	}

	snif = pcap_open_live(dev, 1500, 0, 1000, errbuf);
	if (!snif) {
		fprintf(stderr, "Error open dev: %s\n", errbuf);
		exit(1);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		exit(1);
	}

	len = snprintf(portbuf, MAXNFTYPES * 256, "port %d", ports[0]);
	for (i = 1; i < cnt; ++i) {
		len += snprintf(portbuf + len, MAXNFTYPES * 256, " or port %d", ports[i]);
	}

	if (!x)
		snprintf(filter, 255, "udp and (%s)", portbuf);
	else
		snprintf(filter, 255, "udp and (%s) and host not 62.213.66.39", portbuf);

	if (pcap_compile(snif, &fp, filter, 0, net) < 0) {
		fprintf(stderr, "Compile error %s", pcap_geterr(snif));
		exit(1);
	}
	
	if (pcap_setfilter(snif, &fp) < 0) {
		fprintf(stderr, "Set filter error %s", pcap_geterr(snif));
		exit(1);
	}
	
		

	pcap_loop(snif, -1, process, NULL);
}


int make_connection(void) {
	struct sockaddr_in sin,rsin;

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		syslog(LOG_WARNING, "Socket error: %d", errno);
		return -1;
	}

	bzero(&sin, sizeof(struct sockaddr_in));
	bzero(&rsin, sizeof(struct sockaddr_in));
	sin.sin_family = rsin.sin_family = AF_INET;
	if (bind(sk, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0) {
		syslog(LOG_WARNING, "Bind error: %d", errno);
		close(sk);
		return -1;
	}

	rsin.sin_port   = htons(99);
	//inet_aton("62.213.66.32", &rsin.sin_addr);
	inet_aton("172.16.1.1", &rsin.sin_addr);
	if (connect(sk, (struct sockaddr *) &rsin, sizeof(struct sockaddr)) < 0) {
		syslog(LOG_WARNING, "Connect error: %d", errno);
		close(sk);
		return -1;
	}

	return 0;
}


void parse_buffer(void) ;
#define BUFSIZE	4096*10
char buffer[BUFSIZE + 4096];
int pos = 0;


void process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ip *ip;
	const struct udphdr *udp;
	int len;
	struct in_addr in;
	void *data;
	struct flow_ver5_hdr *fp ,*fps;
	int type;
	unsigned short port;
	struct sfp_t *sfp;
	uint32_t bid;


	ip = (struct sniff_ip*)(packet + 14);
	len = (ip->ip_vhl & 15) * 4;

	if (len < 20) {
		fprintf(stderr,"Invalid Packet\n");
		return;
	}
	if (ip->ip_p != 17) {
		return;
	}

	udp = (struct udphdr *) ((char *) ip + len);
	len = ntohs(udp->len);
	data = (void *)((char *) udp + sizeof(struct udphdr));
	port = ntohs(udp->dest);

	fp = (struct flow_ver5_hdr *) (data);

	fp->version  = ntohs(fp->version);
	fp->count    = ntohs(fp->count);
	fp->flow_sequence = ntohl(fp->flow_sequence);

	sfp = getNf(fp->engine_type,fp->engine_id,port);
	fps =  &sfp->nf;

	if (fps->count) {
		if (fps->flow_sequence == fp->flow_sequence) {
			syslog(LOG_WARNING, "dupl=%d count=%d flow=%u type=%hhd eid=%hhd p=%d\n", fp->version, fp->count, fp->flow_sequence, fp->engine_type, fp->engine_id, port);
		}  else	if (fps->flow_sequence +  fps->count != fp->flow_sequence) {

			if (debug) {
				syslog(LOG_WARNING, "curr=%d count=%d flow=%u type=%hhd eid=%hhd p=%d start=%u\n", fp->version, fp->count, fp->flow_sequence, fp->engine_type, fp->engine_id, port, sfp->start);
				syslog(LOG_WARNING, "prev=%d count=%d flow=%u type=%hhd eid=%hhd p=%d start=%u\n", fps->version, fps->count, fps->flow_sequence, fps->engine_type, fps->engine_id, port, sfp->start);	
			}

			bid = port | fps->engine_type << 16 | fps->engine_id << 24;
			send_piece(sfp->start, fps->flow_sequence + fps->count, bid);
			sfp->start = fp->flow_sequence;
		} else {
			if (!sfp->start)
				sfp->start = fp->flow_sequence;
		}

	}
	
	fps->count = fp->count;
	fps->flow_sequence = fp->flow_sequence;

	// done at getNf
	fps->engine_type = fp->engine_type;
	fps->engine_id = fp->engine_id;
}


void send_piece(uint32_t start, uint32_t end, uint32_t bid) {
	struct sdata sd;
	int rv;

	sd.start = start;
	sd.end   = end;
	sd.bid   = bid;

	if (make_connection() < 0)
		return;

	if (( rv = send(sk, &sd, sizeof(struct sdata), MSG_DONTWAIT)) < 0) {
		syslog(LOG_WARNING, "Connection broken, retrying...\n");
		make_connection();
		return;
	}
	close(sk);
}
