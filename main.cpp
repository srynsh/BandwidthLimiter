#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <bits/stdc++.h>

using namespace std;

#define NFQUEUE_NUM 0
#define BUFFER_SIZE 4096
#define LIMIT 10000000000 // 1 GB/day
#define SPEED_LIMIT 1000000 // 1 MBps

map<unsigned long, unsigned long> user_data_total; // cleared every day by a thread
map<unsigned long, unsigned long> user_data_per_10_seconds; // cleared every 10 seconds by a thread

bool check_local(string addr) {
    // check if the ip addr is of the form 192.168.1.x => user in the router network.
    if (addr.substr(0, 10) == "192.168.1.") {
        return true;
    }

    return false;
}

bool check_local(unsigned long ip) {
    // c0.a8.01 => 192.168.1
    return (ip & 0xffffff00) == 0xc0a80100;
}

bool check_valid(unsigned long ip) {
    if ((ip & 0xff000000) == 0) {
        return false; // 0.0.0.0/24
    }
    if (ip == 0xc0a801ff) {
        return false; // local bc
    }
    if ((ip & 0xff000000) == 0xff000000) {
        return false;
    }
    if ((ip & 0xffff0000) == 0xfea90000) {
        return false;
    }
    if ((ip & 0xe0000000) == 0xe0000000) {
        return false; // 223.0.0.0/4
    }

    return true;
}


int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    u_int32_t id;
    struct iphdr *ip;
    struct tcphdr *tcp;
    char *payload;
    int payload_len;
    bool allow = true;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        // std::cout << ph << std::endl;
    } else {
        printf("scam\n");
    }

    payload_len = nfq_get_payload(nfa, (unsigned char **)&payload);
    if (payload_len > 0) {
        ip = (struct iphdr *)payload;
        // printf("Received IP packet with source address %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        // printf("Received IP packet with destination address %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
        
        unsigned long sa = ntohl(ip->saddr);
        unsigned long da = ntohl(ip->daddr);
        long size_of_packet = ntohs(ip->tot_len);

        string sa_str = inet_ntoa(*(struct in_addr *)&ip->saddr);
        string da_str = inet_ntoa(*(struct in_addr *)&ip->daddr);

        if (!check_valid(sa) || !check_valid(da)) {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        // check if the ip addr is of the form 192.168.1.x => user in the router network.
        if (check_local(sa)) {
            if (user_data_total.find(sa) == user_data_total.end()) {
                user_data_total[sa] = size_of_packet;
                printf("new s %lx\n", sa);
                printf("    d %lx\n", da);
            } else {
                user_data_total[sa] += size_of_packet;
            }

            if (user_data_total[sa] > LIMIT) {
                allow = false;
            }

            printf("user_data_total[%lx] = %ld\n", sa, user_data_total[sa]);
        } else if (check_local(da)) {
            if (user_data_total.find(da) == user_data_total.end()) {
                user_data_total[da] = size_of_packet;
                printf("new d %lx\n", da);
                printf("    s %lx\n", sa);
            } else {
                user_data_total[da] += size_of_packet;
            }

            if (user_data_total[da] > LIMIT) {
                allow = false;
            }

            printf("user_data_total[%lx] = %ld\n", da, user_data_total[da]);
        }
        
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (struct tcphdr *)(payload + (ip->ihl * 4));
            // printf("")
            // printf("%lu\n" , ip->saddr);

            // printf("Received TCP packet with source port %d and destination port %d\n", ntohs(tcp->source), ntohs(tcp->dest));
        }
    }

    if (allow) {
        //cout << "allow" << endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    } else {
        cout << "drop" << endl;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

int main() {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    char buf[BUFFER_SIZE];

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error: nfq_open failed\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_unbind_pf failed\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_bind_pf failed\n");
        exit(1);
    }

    qh = nfq_create_queue(h, NFQUEUE_NUM, &callback, NULL);
    if (!qh) {
        fprintf(stderr, "Error: nfq_create_queue failed\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error: nfq_set_mode failed\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while (1) {
        int len = read(fd, buf, sizeof(buf));
        if (len < 0) {
            fprintf(stderr, "Error: read failed\n");
            exit(1);
        }

        nfq_handle_packet(h, buf, len);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

