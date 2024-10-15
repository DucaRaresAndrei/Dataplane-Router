#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

#define IPv4 0x0800
#define ICMP 1
#define SIZE_MAC 6

int check_destination(struct ether_header *eth_hdr, int interface)
{
	uint8_t mac[SIZE_MAC];
	uint8_t broadcast[SIZE_MAC];
	memset(broadcast, 0xff, SIZE_MAC);

	get_interface_mac(interface, mac);

	if(memcmp(eth_hdr->ether_dhost, mac, SIZE_MAC) != 0 && memcmp(eth_hdr->ether_dhost, broadcast, SIZE_MAC) != 0)
		return 0;

	return 1;
}

//for sorting the route_table
int comparator(const void *a, const void *b) {
	struct route_table_entry *r1 = (struct route_table_entry *) a;
	struct route_table_entry *r2 = (struct route_table_entry *) b;

	if (ntohl(r1->prefix & r1->mask) == ntohl(r2->prefix & r2->mask))
		return (ntohl(r1->mask) - ntohl(r2->mask));
	else 
		return (ntohl(r1->prefix & r1->mask) - ntohl(r2->prefix & r2->mask));
}

//Longest Prefix Match
struct route_table_entry *find_best_route(struct route_table_entry *route_table, int route_table_len, uint32_t d_addr) {
	int left = 0, right = route_table_len - 1;
	struct route_table_entry *best_route = NULL;

	while(left <= right) {
		int mid = (left + right) / 2;

		uint32_t masked_dest_addr = ntohl(d_addr & route_table[mid].mask);
        uint32_t masked_prefix = ntohl(route_table[mid].prefix & route_table[mid].mask);

		if (masked_prefix < masked_dest_addr) {
			left = mid + 1;
		} else if (masked_prefix > masked_dest_addr) {
			right = mid - 1;
		} else {
			best_route = &route_table[mid];
			left = mid + 1;
		}
	}
	
	return best_route;
}

//swap values
void swap(void* a, void* b, size_t size) {
    void* aux = malloc(size);

    memcpy(aux, a, size);
    memcpy(a, b, size);
    memcpy(b, aux, size);

    free(aux);
}

void icmp_message(int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, struct icmphdr *icmp_hdr)
{
	//swap ethernet addresses
	swap(eth_hdr->ether_shost, eth_hdr->ether_dhost, SIZE_MAC);

	//swap ip addresses
	swap(&ip_hdr->saddr, &ip_hdr->daddr, sizeof(uint32_t));

	//create new packet
	char package[MAX_PACKET_LEN];
	memcpy(package, eth_hdr, sizeof(struct ether_header));

	//update len and checksum
	ip_hdr->tot_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->protocol = ICMP;
	ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));

	//update icmp header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((u_int16_t *)icmp_hdr, sizeof(struct icmphdr)));

	//update the packet we want to send back
	memcpy(package + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(package + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, package, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

void ipv4_algorithm(int interface, size_t len, char *buf, struct ether_header *eth_hdr,
					struct route_table_entry *route_table, struct arp_table_entry *arp_table,
					int route_table_len, int arp_table_len)
{
	uint32_t interface_ip = inet_addr(get_interface_ip(interface));

	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	//check if packet destination is this router
	if (interface_ip == ntohl(ip_hdr->daddr)) {
		//Echo reply ICMP message
		icmp_message(interface, eth_hdr, ip_hdr, 0, icmp_hdr);
		return;
	}

	//check if checksum is right
	int original_checksum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != original_checksum)
		return;

	//check if ttl is wrong and throw away the packet
	if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
		//Time exceeded ICMP message
		icmp_message(interface, eth_hdr, ip_hdr, 11, icmp_hdr);
		return;
	} else {
		--(ip_hdr->ttl);
	}

	//find the best entry in the routing table for next hop
	struct route_table_entry *best_route = find_best_route(route_table, route_table_len, ip_hdr->daddr);

	//check if we found an entry
	if (!best_route) {
		//Destination unreachable ICMP message
		icmp_message(interface, eth_hdr, ip_hdr, 3, icmp_hdr);
		return;
	}

	//update checksum
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	uint8_t *mac = malloc(SIZE_MAC);
	get_interface_mac(best_route->interface, mac);

	//find in arp_table the next hop's ip
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == best_route->next_hop) {
			memcpy(eth_hdr->ether_shost, mac, SIZE_MAC);
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, SIZE_MAC);
			send_to_link(best_route->interface, buf, len);

			break;
		}
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *route_table = malloc(sizeof(struct route_table_entry) * 100000);
	int route_table_len = read_rtable(argv[1], route_table);
	qsort(route_table, route_table_len, sizeof(struct route_table_entry), comparator);

	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		//we have to drop the packet if destination is not right
		if(!check_destination(eth_hdr, interface))
			continue;

		if (ntohs(eth_hdr->ether_type) == IPv4) {
			ipv4_algorithm(interface, len, buf, eth_hdr, route_table, arp_table, route_table_len, arp_table_len);
		}
	}
}

