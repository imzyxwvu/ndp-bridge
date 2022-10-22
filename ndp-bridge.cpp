/*
 * Copyright 2022 zyxwvu Shi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <iostream>
#include <cstring>
#include <memory>
#include <vector>
#include <map>
#include <sstream>

#include <sys/socket.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <unistd.h>

class ether_address {
public:
    uint8_t *data() { return m_addr; }
    const uint8_t *data() const { return m_addr; }
    static const size_t size = 6;
    std::string to_string() const;

    bool operator<(const ether_address &other) const {
        return memcmp(m_addr, other.m_addr, sizeof(m_addr)) < 0;
    }
private:
    uint8_t m_addr[6];
};

class ip6_address {
public:
    explicit ip6_address(const std::string &str);
    explicit ip6_address(const uint8_t *src);
    uint8_t *data() { return m_addr.s6_addr; }
    const uint8_t *data() const { return m_addr.s6_addr; }
    bool is_link_local() const { return m_addr.s6_addr[0] == 0xfeu; }
    bool is_multicast() const { return m_addr.s6_addr[0] == 0xffu; }
    static const size_t size = 16;
    std::string to_string() const;

    bool operator<(const ip6_address &other) const {
        return memcmp(m_addr.s6_addr, other.m_addr.s6_addr,
                sizeof(m_addr.s6_addr)) < 0;
    }
private:
    in6_addr m_addr;
};

#define ICMP6_RS 133
#define ICMP6_RA 134
#define ICMP6_NS 135
#define ICMP6_NA 136

class icmp6_packet {
public:
    void set_src_ether(const ether_address &addr);
    void set_dst_ether(const ether_address &addr);
    uint8_t icmp6_type() const { return m_buf[54]; }
    ether_address src_ether() const;
    ip6_address src_ip6() const { return ip6_address(m_buf.data() + 22); }
    ip6_address dst_ip6() const { return ip6_address(m_buf.data() + 38); }
    size_t ip6_payload_len() const;
    bool fib_learnt() const { return m_fib_learnt; }
private:
    size_t locate_tlv_data(uint8_t type) const;
    void update_icmp6_checksum();
    std::vector<uint8_t> m_buf;
    bool m_fib_learnt = false;
    friend class icmp6_pump;
};

class icmp6_pump {
public:
    explicit icmp6_pump(const std::string &if_name);
    virtual ~icmp6_pump();
    int file_no() const { return m_fd; }
    void recv(icmp6_packet &packet);
    void inject(icmp6_packet &packet, bool update_src = true);
private:
    void update_ifindex_hw_addr(const std::string &if_name);
    int m_fd, m_ifindex;
    ether_address m_hw_addr;
    std::map<ip6_address , ether_address> m_fib_neigh;
};

using icmp6_pump_ref = std::shared_ptr<icmp6_pump>;

std::string ether_address::to_string() const {
    char buf[32];
    int len = snprintf(buf, sizeof(buf),
            "%02x:%02x:%02x:%02x:%02x:%02x",
            m_addr[0], m_addr[1], m_addr[2], m_addr[3], m_addr[4], m_addr[5]);
    return std::string(buf, len);
}

ip6_address::ip6_address(const std::string &str) {
    inet_pton(AF_INET6, str.c_str(), &m_addr);
}

ip6_address::ip6_address(const uint8_t *src) {
    memcpy(data(), src, size);
}

std::string ip6_address::to_string() const {
    char buf[64] = {0};
    inet_ntop(AF_INET6, &m_addr, buf, sizeof(buf));
    return std::string(buf);
}

static uint16_t ip6_checksum(uint32_t magic, uint8_t *addr, size_t count)
{
    uint32_t sum = magic;
    for (; count > 1; addr += 2, count -= 2) sum += *(uint16_t *)addr;
    if (count == 1) sum += *addr;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

ether_address icmp6_packet::src_ether() const {
    ether_address addr;
    memcpy(addr.data(), m_buf.data() + 6, addr.size);
    return addr;
}

void icmp6_packet::set_src_ether(const ether_address &addr) {
    if (m_buf.size() < 14)
        throw std::runtime_error("No Ethernet header present");
    memcpy(m_buf.data() + 6, addr.data(), addr.size);
    try {
        size_t src_lla_offset = locate_tlv_data(
                icmp6_type() != ICMP6_NA ? 1 : 2);
        memcpy(m_buf.data() + src_lla_offset, addr.data(), addr.size);
        update_icmp6_checksum();
    }
    catch (std::out_of_range) {}
}

void icmp6_packet::set_dst_ether(const ether_address &addr) {
    if (m_buf.size() < 14)
        throw std::runtime_error("No Ethernet header present");
    memcpy(m_buf.data(), addr.data(), addr.size);
}

size_t icmp6_packet::ip6_payload_len() const {
    return ntohs(*(uint16_t *)(m_buf.data() + 18));
}

size_t icmp6_packet::locate_tlv_data(uint8_t type) const {
    size_t tlv_base;
    switch (icmp6_type()) {
        case ICMP6_RS: tlv_base = 62; break;
        case ICMP6_RA: tlv_base = 70; break;
        case ICMP6_NS: case ICMP6_NA: tlv_base = 78; break;
        default: throw std::invalid_argument("Unknown ICMPv6 type");
    }

    while (tlv_base < m_buf.size()) {
        int item_len = m_buf[tlv_base + 1] * 8;
        if (item_len == 0)
            throw std::invalid_argument("Incorrect TLV item length");
        if (type == m_buf[tlv_base])
            return tlv_base + 2;
        tlv_base += item_len;
    }
    throw std::out_of_range("No option of such type");
}

void icmp6_packet::update_icmp6_checksum() {
    size_t icmp6_len = ip6_payload_len();
    memset(m_buf.data() + 56, 0, 2);
    *(uint16_t *)(m_buf.data() + 56) = ip6_checksum(
            htons(icmp6_len) + htons(0x3a),
            m_buf.data() + 22, 32 + icmp6_len);
}

/* icmp6 && ip6[40] >= 133 */
static sock_filter icmp6_filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 8, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 3, 0, 0x0000003a },
        { 0x15, 0, 5, 0x0000002c },
        { 0x30, 0, 0, 0x00000036 },
        { 0x15, 0, 3, 0x0000003a },
        { 0x30, 0, 0, 0x00000036 },
        { 0x35, 0, 1, 0x00000085 },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 },
};

icmp6_pump::icmp6_pump(const std::string &if_name) {
    m_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (m_fd == -1)
        throw std::runtime_error(strerror(errno));
    update_ifindex_hw_addr(if_name);

    sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_IPV6),
            .sll_ifindex = m_ifindex,
    };
    if (bind(m_fd, (sockaddr *)&sll, sizeof(sll)) == -1) {
        close(m_fd);
        throw std::runtime_error("Failed to apply SO_BINDTODEVICE");
    }

    sock_fprog filter_prg = {
            .len = sizeof(icmp6_filter) / sizeof(struct sock_filter),
            .filter = icmp6_filter
    };
    if (setsockopt(m_fd, SOL_SOCKET, SO_ATTACH_FILTER,
            &filter_prg, sizeof(filter_prg)) == -1) {
        close(m_fd);
        throw std::runtime_error("Failed to attach BPF filter");
    }

}

icmp6_pump::~icmp6_pump() {
    close(m_fd);
    m_fd = -1;
}

void icmp6_pump::recv(icmp6_packet &packet) {
    packet.m_buf.resize(8192);
    packet.m_fib_learnt = false;

    int n_read = read(m_fd, packet.m_buf.data(), packet.m_buf.size());
    if (n_read == -1)
        throw std::runtime_error(strerror(errno));
    packet.m_buf.resize(n_read);

    if (packet.icmp6_type() == ICMP6_NS || packet.icmp6_type() == ICMP6_RS ||
        packet.icmp6_type() == ICMP6_NA || packet.icmp6_type() == ICMP6_RA) {
        auto src_ip6 = packet.src_ip6();
        if (m_fib_neigh.find(src_ip6) == m_fib_neigh.end()) {
            m_fib_neigh.emplace(src_ip6, packet.src_ether());
            packet.m_fib_learnt = true;
        }
    }
}

void icmp6_pump::inject(icmp6_packet &packet, bool update_src) {
    if (update_src)
        packet.set_src_ether(m_hw_addr);

    /* Update dst MAC address for unicast packet */
    auto dst_ip6 = packet.dst_ip6();
    if (!dst_ip6.is_multicast()) {
        auto ether_it = m_fib_neigh.find(dst_ip6);
        if (ether_it == m_fib_neigh.end())
            return;  /* Not this side */
        packet.set_dst_ether(ether_it->second);
    }

    if (write(m_fd, packet.m_buf.data(), packet.m_buf.size()) == -1)
        throw std::runtime_error(strerror(errno));
}

void icmp6_pump::update_ifindex_hw_addr(const std::string &if_name) {
    ifreq ifr = {};
    strcpy(ifr.ifr_ifrn.ifrn_name, if_name.c_str());

    if (ioctl(m_fd, SIOCGIFINDEX, &ifr) == -1)
        throw std::runtime_error(strerror(errno));
    m_ifindex = ifr.ifr_ifru.ifru_ivalue;

    if (ioctl(m_fd, SIOCGIFHWADDR, &ifr) == -1)
        throw std::runtime_error(strerror(errno));
    memcpy(m_hw_addr.data(), ifr.ifr_ifru.ifru_hwaddr.sa_data,
            m_hw_addr.size);
}

static void add_fib_neighbor_route(const ip6_address &dst, const std::string &out_if) {
    std::stringstream ss;
    ss << "ip route add table local " << dst.to_string() << " oif " << out_if;
    system(ss.str().c_str());
}

void run_ndp_bridge(const std::string &inner_if, const std::string &outer_if) {
    icmp6_pump pump_inner(inner_if), pump_outer(outer_if);
    fd_set fds_read;
    while (true) {
        FD_ZERO(&fds_read);
        FD_SET(pump_inner.file_no(), &fds_read);
        FD_SET(pump_outer.file_no(), &fds_read);
        int n_fd = select(
                std::max(pump_inner.file_no(), pump_outer.file_no()) + 1,
                &fds_read, nullptr, nullptr, nullptr);
        if (n_fd < 0)
            throw std::runtime_error("select() failed");

        icmp6_packet pkt;
        if (FD_ISSET(pump_inner.file_no(), &fds_read)) {
            pump_inner.recv(pkt);
            if (pkt.icmp6_type() == ICMP6_RS || pkt.icmp6_type() == ICMP6_NS ||
                    pkt.icmp6_type() == ICMP6_NA) {
                if (pkt.fib_learnt()) {
                    auto src_ip6 = pkt.src_ip6();
                    if (!src_ip6.is_link_local())
                        add_fib_neighbor_route(src_ip6, inner_if);
                }
                pump_outer.inject(pkt);
            }
        }

        if (FD_ISSET(pump_outer.file_no(), &fds_read)) {
            pump_outer.recv(pkt);
            if (pkt.icmp6_type() == ICMP6_RA || pkt.icmp6_type() == ICMP6_NS ||
                    pkt.icmp6_type() == ICMP6_NA)
                pump_inner.inject(pkt);
        }
    }
}

int main(int argc, char *argv[]) {
    std::string inner_if, outer_if;
    int opt;
    while ((opt = getopt(argc, argv, "i:o:")) != -1) {
        switch (opt) {
            case 'i': inner_if = optarg; break;
            case 'o': outer_if = optarg; break;
            default:
                printf("Usage: %s -i <inner if> -o <outer if>\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (inner_if.empty() || outer_if.empty()) {
        fprintf(stderr, "%s: Inner or outer interface not specified.", argv[0]);
        return EXIT_FAILURE;
    }

    run_ndp_bridge(inner_if, outer_if);
    return 0;
}
