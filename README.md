#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int ethernet_len = sizeof(struct ether_header);

    // 최소한 Ethernet + IP 헤더 크기만큼 있어야 함
    if (pkthdr->len < ethernet_len + sizeof(struct ip)) {
        printf("패킷 너무 짧음 (IP 헤더까지 도달 불가)\n");
        return;
    }

    struct ether_header *eth = (struct ether_header *)packet;
    struct ip *ip_hdr = (struct ip *)(packet + ethernet_len);

    // TCP만 처리
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_header_len = ip_hdr->ip_hl * 4;
    if (pkthdr->len < ethernet_len + ip_header_len + sizeof(struct tcphdr)) {
        printf("패킷 너무 짧음 (TCP 헤더까지 도달 불가)\n");
        return;
    }

    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ethernet_len + ip_header_len);

    int tcp_header_len = tcp_hdr->th_off * 4;
    int total_header_len = ethernet_len + ip_header_len + tcp_header_len;

    if (pkthdr->len < total_header_len) {
        printf("패킷 너무 짧음 (페이로드까지 도달 불가)\n");
        return;
    }

    const u_char *payload = packet + total_header_len;
    int payload_len = pkthdr->len - total_header_len;

    // 4. 결과 출력
    printf("\n[패킷 크기: %d bytes]", pkthdr->len);
    printf("\nEthernet: %02x:%02x:%02x:%02x:%02x:%02x → %02x:%02x:%02x:%02x:%02x:%02x",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("\nIP: %s → %s", inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst));
    printf("\nTCP: 포트 %d → %d", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

    // 5. 메시지 출력 (16진수 + ASCII)
    if (payload_len > 0) 
    {
        printf("\n메시지 (%d bytes):\n", payload_len);

        for (int i = 0; i < payload_len; i++) 
        {
            printf("%02x ", payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
    }
    printf("\n----------------------------------------\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 네트워크 장치 선택
    char *dev = pcap_lookupdev(errbuf);
    if (!dev) 
    {
        fprintf(stderr, "장치 찾기 실패: %s\n", errbuf);
        return 1;
    }

    // 패킷 캡처 핸들 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) 
    {
        fprintf(stderr, "핸들 열기 실패: %s\n", errbuf);
        return 1;
    }

    // TCP 패킷만 필터링 (BPF 컴파일)
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) 
    {
        fprintf(stderr, "필터 컴파일 실패\n");
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) 
    {
        fprintf(stderr, "필터 적용 실패\n");
        return 1;
    }

    // 패킷 캡처 시작 (무한 루프)
    printf("TCP 패킷 캡처 시작 (종료: Ctrl+C)\n");

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}
