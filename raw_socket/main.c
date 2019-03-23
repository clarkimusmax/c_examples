/*
 * Simple example of Linux raw sockets.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/*
 * Define DEBUG to also print next protocol for ethernet and IP printers:
 * #define DEBUG
 */

/* Max packet buffer size */
#define PACKET_BUFFER_LEN 1024 * 4

/*
 * Prints usage.
 */
void usage (char **argv)
{
	printf("Usage: %s -i interface [-p protocol]\n", argv[0]);
}

/*
 * Function to print raw bytes.  Can be useful for debugging.
 */
#ifdef DEBUG
void  print_hex (void *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		printf("%02x ", ((char*)data)[i]&0xff);
	}
	puts("");
}
#endif

/*
 * Function to print MAC addresses, given an ethernet frame and length.
 */
int print_ether (void *packet, size_t len)
{
	/*
	 * The ethhdr struct is defined in linux/if_ether.h:
	 *
	 * struct ethhdr {
	 * 	unsigned char   h_dest[ETH_ALEN];
	 *	unsigned char   h_source[ETH_ALEN];
	 *	__be16          h_proto;
	 * } __attribute__((packed));
	 */
	struct ethhdr *frame = packet;

	if (sizeof(struct ethhdr) > len) {
		printf(" Ethernet: Incomplete frame");
		return 0;
	}

	/* Print L2 address info */
	printf(" Ethernet: %02x:%02x:%02x:%02x:%02x:%02x->%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char)frame->h_source[0],
		(unsigned char)frame->h_source[1],
		(unsigned char)frame->h_source[2],
		(unsigned char)frame->h_source[3],
		(unsigned char)frame->h_source[4],
		(unsigned char)frame->h_source[5],
		(unsigned char)frame->h_dest[0],
		(unsigned char)frame->h_dest[1],
		(unsigned char)frame->h_dest[2],
		(unsigned char)frame->h_dest[3],
		(unsigned char)frame->h_dest[4],
		(unsigned char)frame->h_dest[5]);
#ifdef DEBUG
	printf(" (next proto: %04x)", ntohs(frame->h_proto));
#endif

	/* Return next protocol */
	return ntohs(frame->h_proto);
};

/*
 * Function to print IP addresses, given an ethernet frame and length.
 */
int print_ip (void *packet, size_t len)
{
	/* The iphdr structure is defined in netinet/ip.h:
	 *
	 * struct iphdr {
	 * 	#if __BYTE_ORDER == __LITTLE_ENDIAN
	 *      unsigned int ihl:4;
	 *      unsigned int version:4;
	 *      #elif __BYTE_ORDER == __BIG_ENDIAN
	 *      unsigned int version:4;
	 *      unsigned int ihl:4;
	 * 	#endif
	 *      u_int8_t tos;
	 *      u_int16_t tot_len;
	 *      u_int16_t id;
	 *      u_int16_t frag_off;
	 *      u_int8_t ttl;
	 *      u_int8_t protocol;
	 *      u_int16_t check;
	 *      u_int32_t saddr;
	 *      u_int32_t daddr;
	 * };
	 *
	 * Note that this may not be the complete IP header.  We have to do
	 * some extra work to determine if IP options are included.
	 *
	 * If you're not familiar with low-level networking, take a moment to
	 * look at the relation between the C structure (above) and the RFC 791
	 * example header (below).
	 *
	 * Per RFC 791 (Internet Protocol) section 3.1:
	 * 	0                   1                   2                   3
	 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |Version|  IHL  |Type of Service|          Total Length         |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |         Identification        |Flags|      Fragment Offset    |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |  Time to Live |    Protocol   |         Header Checksum       |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |                       Source Address                          |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |                    Destination Address                        |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |                    Options                    |    Padding    |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *                       Example Internet Datagram Header
	 */

	struct iphdr *iph;
	/* Max IP string size: "xxx.xxx.xxx.xxx\0" - 16 bytes
	 * 	or
	 * Use INET_ADDRSTRLEN, because someone else already figured this out
	 */
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];

	/*
	 * We need to get a pointer to our IP header (which is past the
	 * ethernet header), but also ensure we're not exceeding bounds.
	 *
	 * The following code may not account for the entire size of the IP
	 * header, including options, but the last thing in the header we need
	 * to access is the destination address, which occurs before the
	 * options, so we don't have to worry about exact header size (yet).
	 */
	if (sizeof(struct ethhdr) + sizeof(struct iphdr) > len) {
		printf(" IP: Incomplete IP Header");
		return 0;
	}

	/* Pointer to our iphdr struct */
	iph = (struct iphdr*)((char*)packet + sizeof(struct ethhdr));

	/*
	 * Convert IP addresses to strings
	 *
	 * inet_ntop can return an error, but only if we screwed up the address
	 * length or IP isn't supported.
	 * */
	(void) inet_ntop (AF_INET, (struct in_addr*)&(iph->saddr), src_ip, INET_ADDRSTRLEN);
	(void) inet_ntop (AF_INET, (struct in_addr*)&(iph->daddr), dst_ip, INET_ADDRSTRLEN);

	/* Print address info */
	printf(" IP: %s->%s", src_ip, dst_ip);
#ifdef DEBUG
	printf(" (next proto: %02x)", iph->protocol);
#endif

	return iph->protocol;
}

/*
 * Function to print TCP ports, when given an ethernet frame and length.
 */
void print_tcp (void *packet, size_t len)
{
	/*
	 * The tcphdr structure is defined in netinet/tcp.h:
	 * struct tcphdr {
	 * 	u_int16_t source;
	 * 	u_int16_t dest;
	 * 	... truncated for brevity ...
	 * };
	 *
	 * Similar to the IP header, the TCP header also may have a variable
	 * length.  This will not affect how we're processing any of this since
	 * we're moving further into the packet than the port numbers.
	 *
	 * The TCP header is described in RFC 793 section 3.1:
	 * 	0                   1                   2                   3
	 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |          Source Port          |       Destination Port        |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |                        Sequence Number                        |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |                    Acknowledgment Number                      |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |  Data |           |U|A|P|R|S|F|                               |
	 *      | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
	 *      |       |           |G|K|H|T|N|N|                               |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |           Checksum            |         Urgent Pointer        |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |                    Options                    |    Padding    |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      |                             data                              |
	 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	struct tcphdr *tcph;
	struct iphdr *iph;
	unsigned char iph_len;

	/*
	 * Similar to the IP print function, we need to move past the layer 2
	 * and 3 headers in order to access the TCP header.  This was simple
	 * enough to do in the IP function because we only had to add the size
	 * of the ethhdr structure.  This is a little more complicated because
	 * the length of the IP header is variable.
	 */
	if (sizeof(struct ethhdr) + sizeof(struct iphdr) > len) {
		printf(" Incomplete IP Header");
		return;
	} else {
		iph = (struct iphdr*)((char*)packet + sizeof(struct ethhdr));

		/*
		 * Per RFC 791 section 3.1:
		 * IHL:  4 bits
		 * 	Internet Header Length is the length of the internet header in 32
		 * 	bit words, and thus points to the beginning of the data.  Note that
		 *      the minimum value for a correct header is 5.
		 */
		iph_len = iph->ihl * 4;

		if (sizeof(struct ethhdr) + iph_len > len) {
			printf(" Incomplete TCP Header");
			return;
		}

		/*
		 * Be careful with pointer math!
		 * 	iph + 1 is not equal to (char*)iph + 1
		 *
		 * When you add something to a pointer, there's an implicit:
		 * 	"* sizeof(pointer type)"
		 *
		 * Therefore, iph + 1 is equivalent to:
		 * 	[address of iph] + (1 * sizeof(struct iphdr))
		 * 		OR
		 * 	[address of iph] + (1 * 20)
		 *
		 * Whereas (char*)iph + 1 is equivalent to:
		 * 	[address of iph] + (1 * sizeof(char))
		 * 		OR
		 * 	[address of iph] + (1 * 1)
		 */
		tcph = (struct tcphdr*)((char*)iph + iph_len);

		/*
		 * or, equivalently:
		 *
		 * tcph = (char*)packet + sizeof(ethhdr) + iph_len;
		 */
	}

	/*
	 * That was a lot of code to do some pretty simple stuff.  The code can
	 * be abbreviated to something like this.  It may not be as easy to
	 * read, but it eliminates the need to store a pointer to the IP header
	 * and the IP header length.
	 *
	 * if (sizeof(ethhdr) + sizeof(iphdr) > len ||
	 * 	sizeof(ethhdr) + ((struct iph*)(packet + sizeof(ethhdr)))->ihl*4 > len) {
	 * 	printf(" Incomplete Headers");
	 * 	return;
	 * }
	 * tcph = (char*)packet + sizeof(ethhdr) + ((struct iph*)(packet + sizeof(ethhdr)))->ihl*4;
	 */

	printf(" TCP: %u->%u", ntohs(tcph->source), ntohs(tcph->dest));
}

void print_udp (void *packet, size_t len)
{
	/*
	 * The struct udphdr is defined in netinet/udp.h:
	 * struct udphdr {
	 * 	u_int16_t source;
	 *      u_int16_t dest;
	 *      u_int16_t len;
	 *      u_int16_t check;
	 * };
	 *
	 * You may notice that the ports in the UDP header are in the exact same
	 * location as with TCP.  Knowing the similarities could help determine
	 * when it's appropriate to reuse code.  This function is nearly
	 * equivalent to the previous TCP printing function.
	 *
	 * From RFC 768:
	 *	0      7 8     15 16    23 24    31
	 *      +--------+--------+--------+--------+
	 *      |     Source      |   Destination   |
	 *      |      Port       |      Port       |
	 *      +--------+--------+--------+--------+
	 *      |                 |                 |
	 *      |     Length      |    Checksum     |
	 *      +--------+--------+--------+--------+
	 */

	struct udphdr * udph;

	/* Ensure we have enough packet to access the UDP header */
	if (sizeof(struct ethhdr) + sizeof(struct iphdr) > len ||
		sizeof(struct ethhdr) + ((struct iphdr*)((char*)packet + sizeof(struct ethhdr)))->ihl*4 > len) {
		printf(" Incomplete Headers");
		return;
	}
	udph = (struct udphdr*)((char*)packet + sizeof(struct ethhdr) + ((struct iphdr*)((char*)packet + sizeof(struct ethhdr)))->ihl*4);

	/* Print ports */
	printf(" UDP: %u->%u", ntohs(udph->source), ntohs(udph->dest));
}

/*
 * Main function
 */
int main (int argc, char *argv[])
{
	int opt;
	int i;
	int tcp = 0, udp = 0, l4;
	int sock;
	int ret = 0;
	size_t packet_count = 0;
	ssize_t bytes_recv;
	char *interface = NULL;
	void *packet;

	while ((opt = getopt(argc, argv, "i:p:")) != -1) {
		switch (opt) {
		case 'i':
			interface = optarg;
			break;
		case 'p':
			if (strlen(optarg) == 3) {
				if (!strcmp(optarg, "tcp")) {
					tcp++;
					break;
				} else if (!strcmp(optarg, "udp")) {
					udp++;
					break;
				}
			}
			puts("-p requires: \"tcp\" or \"udp\"");
			exit(1);
		case '?':
			if (optopt == 'i' || optopt == 'p') {
				fprintf(stderr, "-%c requires an argument\n", optopt);
				usage(argv);
				exit(1);
			} else if (isprint(optopt)) {
				fprintf(stderr, "Unknown option: '-%c'\n", optopt);
				usage(argv);
				exit(1);
			} else {
				fprintf(stderr, "Unknown option: '%x'\n", optopt);
				usage(argv);
				exit(1);
			}
		default:
			abort();
		}
	}

	for (i = optind; i < argc; i++) {
		fprintf(stderr, "Invalid argument: %s\n", argv[i]);
		exit(1);
	}

	if (!interface) {
		fprintf(stderr, "You must specify an interface\n");
		usage(argv);
		exit(1);
	}

	/* You have to love the ternary operator */
	printf("Listening on %s for protocol %s\n",
		interface,
		(tcp && udp)? "all" : (tcp) ? "TCP" : (udp) ? "UDP" : "IP");

	/* Create raw socket */
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1) {
		perror("socket");
		exit(1);
	}

	/* Bind socket to interface */
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) == -1) {
		perror("setsockopt");
		ret = 1;
		goto close_socket_and_exit;
	}

	/* Get memory for packet */
	packet = malloc(PACKET_BUFFER_LEN);
	if (!packet) {
		fprintf(stderr, "Out of memory.\n");
		ret = 1;
		goto close_socket_and_exit;
	}

	/* Capture loop */
	while (1) {
		/* Get a packet */
		bytes_recv = recvfrom(sock, packet, PACKET_BUFFER_LEN, 0, NULL, NULL);
		if (bytes_recv < 1) {
			perror("recvfrom");
			ret = 1;
			goto free_packbuf_and_exit;
		}

		printf("#%zu:", packet_count++);

		/*
		 * Start printing packet info
		 *
		 * Each of these functions will print infomation corresponding
		 * to their protocol and return the next layer's protocol
		 * number (excepting the TCP and UDP functions).
		 */

		/* Ethernet */
		if (print_ether(packet, bytes_recv) == ETH_P_IP) {
			/* IP */
			l4 = print_ip(packet, bytes_recv);
			if (tcp && l4 == IPPROTO_TCP) {
				/* TCP */
				print_tcp(packet, bytes_recv);
			} else if (udp && l4  == IPPROTO_UDP) {
				/* UDP */
				print_udp(packet, bytes_recv);
			}
		}
		puts("");
	}

free_packbuf_and_exit:
	free(packet);
close_socket_and_exit:
	while (close(sock) && errno == EINTR);
	if (errno)
		perror("close");

	return ret;
}
