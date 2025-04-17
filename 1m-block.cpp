#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unordered_set>
#include <string>
#include <fstream>
#include <sstream>
#include <sys/time.h>

#define HOST_KEYWORD "Host: "

std::unordered_set<std::string> blocklist;

void load_blocklist(const char* filename) {
    struct timeval start, end;
    gettimeofday(&start, NULL);

    std::ifstream file(filename);
    if (!file.is_open()) {
        perror("open blocklist");
        exit(1);
    }

    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string rank, domain;
        std::getline(ss, rank, ',');
        std::getline(ss, domain);
        blocklist.insert(domain);
    }

    gettimeofday(&end, NULL);
    long diff_usec = (end.tv_sec - start.tv_sec) * 1000000L + (end.tv_usec - start.tv_usec);
    printf("Loaded %zu sites in %ld us\n", blocklist.size(), diff_usec);
}

int check_http_host(unsigned char *data, int size) {
    if (size <= 0) return 0;

    struct iphdr *ip = (struct iphdr *)data;
    if (ip->protocol != IPPROTO_TCP) return 0;

    int ip_header_len = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(data + ip_header_len);
    int tcp_header_len = tcp->doff * 4;

    unsigned char *payload = data + ip_header_len + tcp_header_len;
    int payload_len = size - ip_header_len - tcp_header_len;

    if (payload_len <= 0) return 0;


    if (strncmp((char *)payload, "GET", 3) != 0 &&
        strncmp((char *)payload, "POST", 4) != 0 &&
        strncmp((char *)payload, "HEAD", 4) != 0)
        return 0;

    char *host_pos = (char *)memmem(payload, payload_len, HOST_KEYWORD, strlen(HOST_KEYWORD));
    if (!host_pos) return 0;

    host_pos += strlen(HOST_KEYWORD);
    char *end = strchr(host_pos, '\r');
    if (!end) return 0;

    int host_len = end - host_pos;
    char host_value[256] = {0};
    strncpy(host_value, host_pos, host_len);
    host_value[host_len] = '\0';

    printf("Detected Host: %s\n", host_value);

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    bool blocked = blocklist.count(std::string(host_value)) > 0;

    gettimeofday(&t2, NULL);
    long search_us = (t2.tv_sec - t1.tv_sec) * 1000000L + (t2.tv_usec - t1.tv_usec);
    printf("Search time: %ld us\n", search_us);

    if (blocked) {
        printf("Blocked Host matched: %s\n", host_value);
        return 1;
    }

    return 0;
}

static u_int32_t get_payload(struct nfq_data *tb, unsigned char **payload_data, int *payload_len) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    u_int32_t id = 0;
    if (ph) id = ntohl(ph->packet_id);
    *payload_len = nfq_get_payload(tb, payload_data);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    unsigned char *pkt_data = NULL;
    int len = 0;
    u_int32_t id = get_payload(nfa, &pkt_data, &len);

    int drop = check_http_host(pkt_data, len);
    return nfq_set_verdict(qh, id, drop ? NF_DROP : NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "syntax : netfilter-test <top-1m.csv>\n");
        exit(1);
    }

    load_blocklist(argv[1]);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[4096] __attribute__ ((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}

