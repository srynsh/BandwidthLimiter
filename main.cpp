#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <thread>
#include <mutex>
#include <time.h>

using namespace std;

#define NFQUEUE_NUM 0
#define BUFFER_SIZE 4096
#define LIMIT 1000000000 // 1 GB/day
#define SPEED_LIMIT 100000//00 // 1 MBps

map<unsigned long, unsigned long> user_data_total; // cleared every day by a thread
map<unsigned long, unsigned long> user_data_speed; 

// one global lock for each map
mutex tot_data_mutex;
mutex speed_mutex;

set<unsigned short> blacklisted_tcp;
set<unsigned short> blacklisted_udp;
set<unsigned long> blacklisted_ip;

void load_blacklist_files() {
    FILE *fp_ip = fopen("ip_blacklist.txt", "r");
    FILE *fp_tcp  = fopen("tcp_blacklist.txt", "r");
    FILE *fp_udp = fopen("udp_blacklist.txt", "r");
    char line[16];

    while (fgets(line, 16, fp_ip) != NULL) {
        unsigned long blocked_ip = ntohl(inet_addr(line));
        printf("ip = %08lx\n", blocked_ip);
        blacklisted_ip.insert(blocked_ip);
    }

    unsigned short port_num;
    while (fscanf(fp_tcp, "%hu", &port_num) == 1) {
        printf("tcp port = %hu\n", port_num);
        blacklisted_tcp.insert(port_num);
    }

    while (fscanf(fp_udp, "%hu", &port_num) == 1) {
        printf("udp port = %hu\n", port_num);
        blacklisted_udp.insert(port_num);
    }
}

bool check_local(unsigned long ip) {
    // 10.42.0.0/24
    // 10.42.0.x => 0a.2a.00.
    return (ip & 0xffffff00) == 0x0a2a0000;

    // 192.168.1.0/24
    // 192.168.1 => c0.a8.01
    //return (ip & 0xffffff00) == 0xc0a80100;
}

bool check_valid(unsigned long ip) {
    if ((ip & 0xff000000) == 0) {
        return false; // 0.0.0.0/8 (reserved)
    }
    if ((ip & 0xff) == 0xff) {
        return false; // x.x.x.255 (broadcast)
    }
    if ((ip & 0xffff0000) == 0xfea90000) {
        return false; // 254.169.0.0/16 (link local)
    }
    if ((ip & 0xe0000000) == 0xe0000000) {
        return false; // 224.0.0.0/3 (multicast + reserved)
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
    } else {
        // scam
        id = 0;
    }

    payload_len = nfq_get_payload(nfa, (unsigned char **)&payload);

    if (payload_len > 0) {
        ip = (struct iphdr *)payload;
        
        unsigned long sa = ntohl(ip->saddr);
        unsigned long da = ntohl(ip->daddr);

        if (!check_valid(sa) || !check_valid(da)) {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        if (check_local(da) && check_local(sa)) {
            // intra network
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        unsigned long local_ip = sa;
        unsigned long foreign_ip = da;
        bool is_source_local = 1;

        if (check_local(da)) {
            local_ip = da;
            foreign_ip = sa;
            is_source_local = 0;
        }

        if (blacklisted_ip.find(foreign_ip) != blacklisted_ip.end()) {
            cout << "drop\n";
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        tot_data_mutex.lock();
        speed_mutex.lock();

        // check if the ip addr is of the form 192.168.1.x => user in the router network.
        if (user_data_total[local_ip] > LIMIT || user_data_speed[local_ip] > SPEED_LIMIT) {
            allow = false;
        } else {
            long size_of_packet = ntohs(ip->tot_len);
            user_data_total[local_ip] += size_of_packet;
            user_data_speed[local_ip] += size_of_packet;
        }

        // printf("user_data_speed[%lx] = %ld\n", local_ip, user_data_speed[local_ip]);

        speed_mutex.unlock();
        tot_data_mutex.unlock();

        if (ip->protocol == IPPROTO_TCP) {
            cout << "tcp" << endl;
            tcp = (struct tcphdr *)(payload + (ip->ihl * 4));
            cout << ntohs(tcp->th_sport) << " " << ntohs(tcp->th_dport) << endl;
            printf("%08lx %08lx\n", sa, da);

            int block_port = ntohs(is_source_local ? tcp->th_dport : tcp->th_sport);

            if (blacklisted_tcp.find(block_port) != blacklisted_tcp.end()) {
                allow = 0;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            cout << "udp\n";
            struct udphdr *udp = (struct udphdr *)(payload + (ip->ihl * 4));

            int port = ntohs(is_source_local ? udp->uh_dport : udp->uh_sport);

            if (blacklisted_udp.find(port) != blacklisted_udp.end()) {
                allow = 0;
            }
        }
    }

    if (allow) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    } else {
        cout << "drop\n";
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

void packet_main() {
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
}

void clear_map_tot() {
    while (1) {
        sleep(3600*24);
        tot_data_mutex.lock();
        user_data_total.clear();
        tot_data_mutex.unlock();
    }
}

void clear_map_speed() {
    while(1) {
        usleep(100000);
        speed_mutex.lock();
        user_data_speed.clear();
        speed_mutex.unlock();
    }   
}

int main() {
    load_blacklist_files();

    thread t1(packet_main);
    thread t2(clear_map_speed);
    thread t3(clear_map_tot);

    t1.join();
    t2.join();
    t3.join();

    return 0;
}
