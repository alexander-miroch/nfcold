#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include "proto.h"



void store(struct sdata *);

struct diap_t {
	uint32_t start,end;
	time_t time;
};

#define MAX_DIAPS	65535

struct stream_t {
	uint32_t id;
	struct diap_t diaps[MAX_DIAPS];
	int count;
};

struct stream_t streams[MAXNFTYPES];
int check_stream(struct stream_t *);
void check(int) ;

struct stream_t *getStream(uint32_t id) {
	int i;

	for (i = 0 ; i < MAXNFTYPES; ++i) {
		if (!streams[i].id)
			break;

		if (streams[i].id == id)
			return &streams[i];
	}

	if (i == MAXNFTYPES - 1) {
		fprintf(stderr, "Too many streams");
		return NULL;
	}

	streams[i].id = id;
	return &streams[i];
}

int rate = 1;
#define INTERVAL (15 * 60)

int main(int argc, char *argv[]) {

	int sk, csk;
	struct sockaddr_in sin, rsin;
	socklen_t slen;
	int rv;
	struct sdata sd;
	int optval = 1;
	int i;


	openlog("nflow-monitor", LOG_NDELAY, LOG_LOCAL1);
	if (daemon(0,0) < 0) {
		perror("daemon");
		exit(1);
	}
		

	bzero(streams, sizeof(struct stream_t) * MAXNFTYPES);
	//setvbuf(stdout, 0, _IONBF, 0);
	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		perror("Socket");
		exit(1);
	}

	if (argc > 1)
		rate = atoi(argv[1]);


	setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	signal(SIGALRM, check);


	alarm(INTERVAL);
	bzero(&sin, sizeof(struct sockaddr_in));
        bzero(&rsin, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(99);
	inet_aton("172.16.1.1", &sin.sin_addr);
	if (bind(sk, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(sk, 1024) < 0) {
		perror("listen");
		exit(1);
	}

	slen = sizeof (struct sockaddr);
	while (( csk = accept(sk, (struct sockaddr *) &rsin, &slen))) {
		if (csk < 0) {
			if (errno == EAGAIN) continue;
			syslog(LOG_WARNING, "Error while accept %d", errno);
			continue;
		}

		rv = recv(csk, &sd, sizeof(struct sdata), 0);
		if (rv < 0) {
			close(csk);
			syslog(LOG_WARNING, "Error recv: %d\n", errno);
			continue;
		}
		if (rv != sizeof(struct sdata)) {
			close(csk);
			syslog(LOG_WARNING, "Invalid packet %d", rv);
			continue;
		}

		store(&sd);
		close(csk);
	}


}

static int cmpdiaps(const void *v1, const void *v2) {
	struct diap_t *d1 = (struct diap_t *) v1;
	struct diap_t *d2 = (struct diap_t *) v2;

	return (d1->start > d2->start) ? 1 : -1;
}


void check(int sig) {
	int i;
	int gaps = 0;

	for (i = 0 ; i < MAXNFTYPES; ++i) {
		if (!streams[i].id)
			break;
	
		gaps += check_stream(&streams[i]);
	}

	if (gaps >= rate)
		syslog(LOG_WARNING, "Total gaps: %d\n", gaps);

	alarm(INTERVAL);
}

#define SECONDS 60

int check_stream(struct stream_t *stream) {
	int total;
	time_t now;
	int idx;
	uint32_t start,end = 0;
	int j,i, rebase = 0;
	int gaps = 0;

	total = stream->count;
	if (!total)
		return 0;

	qsort(stream->diaps, stream->count, sizeof(struct diap_t), cmpdiaps);
	time(&now);

	for (idx = 0; idx < total; idx++) {
		if (stream->diaps[idx].time > now - SECONDS) {
			rebase = 1;
			break;
		}

		if (end && end != stream->diaps[idx].start) {
			syslog(LOG_WARNING, "Missing for port %d prev=%u-%u, cur=%u-%u time=%lu-%lu\n", 
			stream->id & 0xffff, start, end, stream->diaps[idx].start, stream->diaps[idx].end, stream->diaps[idx].time, now);
			gaps++;
		} 

		start = stream->diaps[idx].start;
		end   = stream->diaps[idx].end;
	}

	if (!rebase) {
		stream->count = 0;
		return gaps;
	}

	for (j = idx, i = 0; j < total; i++, j++) {
		memcpy(&stream->diaps[i], &stream->diaps[j], sizeof (struct diap_t));
	}

	stream->count = total - idx;
	return gaps;
}

void store(struct sdata *sd) {
	struct stream_t *stream;
	int idx;

	stream = getStream(sd->bid);
	if (!stream)
		return;	

	idx = stream->count++;
	
	stream->diaps[idx].start = sd->start;
	stream->diaps[idx].end   = sd->end;
	stream->diaps[idx].time   = time(NULL);

}
