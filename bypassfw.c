/*
 * bypassfw.c
 * Bypass a host firewall with a tap device and pcap
 * By J. Stuart McMurray
 * Created 20190503
 * Last Modified 20190503
 */

#include <sys/types.h>

#include <net/if_tun.h>

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pcap.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* SNAPLEN is the maximum size of a capture to read */
#define SNAPLEN 65535

#define UNPRIVUSER "nobody"   /* Unpriviledged user to which to drop perms */
#define TAPPREFIX  "/dev/tap" /* Prefix of tap device filename */

void usage();
void set_filter(pcap_t *p, const char *f, const char *d);
void *inject(void *a);
void sniff(u_char *u, const struct pcap_pkthdr *hdr, const u_char *pkt);

struct injector {
        pcap_t *p; /* Pcap handle */
        int tfd;   /* Tap device fd */
};

int
main(int argc, char **argv)
{
        int tfd;
        pcap_t *p;
        char errbuf[PCAP_ERRBUF_SIZE+1];
        pthread_attr_t attr;
        pthread_t tid;
        struct injector inj;
        char *rp, *ch;
        struct passwd *pw;

        /* TODO: Pledge */
        /* TODO: Unveil */

        /* Get nobody's info */
	if (NULL == (pw = getpwnam(UNPRIVUSER)))
		err(19, "getpwnam");
        if (0 != chdir("/"))
                err(20, "chdir");

        /* Make sure we have arguments */
        if (1 == argc || 0 == strcmp(argv[1], "-h"))
                usage();

        /* Make sure the tap device is a child of /dev/tap */
        if (NULL == (rp = realpath(argv[1], NULL)))
                err(12, "realpath");
        if (0 != strncmp(TAPPREFIX, rp, strlen(TAPPREFIX)))
                errx(13, "invalid tap device: %s", realpath(argv[1], NULL));
        for (ch = rp + strlen(TAPPREFIX); '\0' != *ch; ++ch)
               if (!isdigit(*ch))
                      errx(14, "invalid tap device"); 

        /* We'll only need these two files, and only during initialization */
        if (0 != unveil(rp, "rw"))
                err(15, "unveil");
        if (0 != unveil("/dev/bpf", "rw"))
                err(21, "unveil");

        /* Open the tap device */
        if (-1 == (tfd = open(rp, O_RDWR|O_CLOEXEC)))
                err(1, "open");
        if (0 != unveil(rp, ""))
                err(17, "unveil");
        free(rp); rp = NULL;

        /* Grab the device for pcapping */
        bzero(errbuf, sizeof(errbuf));
        if (NULL == (p = pcap_open_live(argv[2], SNAPLEN, 1, 10, errbuf)))
                errx(2, "pcap_open_live: %s", errbuf);
        if (0 != unveil("/dev/bpf", ""))
                err(22, "unveil");

        /* Done with all the file access, don't let any more files be made
         * visible */
        if (0 != unveil(NULL, NULL))
                err(18, "unveil");

	/* Drop to nobody */
	if (setgroups(1, &pw->pw_gid) == -1)
		err(1, "setgroups() failed");
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		err(1, "setresgid() failed");
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		err(1, "setresuid() failed");

        /* Set the filter if we have one */
        if (4 == argc)
                set_filter(p, argv[3], argv[2]);

	/* Have to call pledge(3) after pcap_setfilter :( */
        if (0 != pledge("stdio", ""))
                err(16, "pledge");

        /* Start reading from the device and injecting to the network */
        inj.p   = p;
        inj.tfd = tfd;
        if (-1 == pthread_attr_init(&attr))
                err(1, "pthread_attr_init");
        if (-1 == pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
                err(1, "pthread_attr_setdetachstate");
        if (0 != pthread_create(&tid, NULL, inject, &inj))
                err(6, "pthread_create");

        /* Sniff frames and send them to the kernel */
        if (0 != pcap_loop(p, -1, sniff, (u_char *)&tfd))
                errx(7, "pcap_loop: %s", pcap_geterr(p));

        /* Unpossible */
        return 8; 


}

/* usage prints a simple usage statement */
void
usage()
{
        fprintf(stderr, "Usage: %s tapdev netif [filter]\n", getprogname());
        exit(1);
}

/* set_filter sets a the bpf filter f on the pcap handle p using device d.  It
 * terminates the program on error. */
void
set_filter(pcap_t *p, const char *f, const char *d)
{
        struct bpf_program program;
        bpf_u_int32 net, mask;
        char errbuf[PCAP_ERRBUF_SIZE+1];

        /* Compile filter program */
        bzero(errbuf, sizeof(errbuf));
        if (0 != pcap_lookupnet(d, &net, &mask, errbuf))
                errx(3, "pcap_lookupnet: %s", errbuf);
        if (0 != pcap_compile(p, &program, f, 1, mask))
                errx(4, "pcap_compile: %s", pcap_geterr(p));

        /* Apply it to the capture handle */
        if (0 != pcap_setfilter(p, &program))
                errx(5, "pcap_setfilter: %s", pcap_geterr(p));
        pcap_freecode(&program);
}

/* inject takes a pointer to an inject and injects frames read from its tfd to
 * its p. */
void *
inject(void *a)
{
        char buf[SNAPLEN+1];
        ssize_t n;
        struct injector *inj;

        /* Argument is actually an injector */
        inj = (struct injector *)a;

        for (;;) {
                /* Read a frame */
                switch (n = read(inj->tfd, buf, sizeof(buf))) {
                        case -1: /* Error */
                                err(8, "read");
                        case 0: /* EOF */
                                errx(9, "EOF");
                }
                /* Send it out */
                if (-1 == pcap_inject(inj->p, buf, (size_t)n))
                        errx(10, "pcap_inject: %s", pcap_geterr(inj->p));
        }
}

/* sniff injects sniffed frames to the kernel via the passed-in file
 * descriptor, which should be for a tap device. */
void
sniff(u_char *u, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
        int tfd;

        /* Tap device fd */
        tfd = *(int *)u;

        /* Make sure we got the entire packet */
        if (hdr->caplen < hdr->len) {
                fprintf(stderr, "Short read (%"PRIu32" < %"PRIu32")\n",
                                hdr->caplen,
                                hdr->len);
                return;
        }

        /* Send it to the tap device */
        if (-1 == write(tfd, pkt, hdr->caplen))
                err(11, "write");
}
