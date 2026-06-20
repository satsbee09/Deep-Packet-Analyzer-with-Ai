#include "parser/packet_parser.h"
#include "parser/sni_extractor.h"
#include <arpa/inet.h>
#include <cctype>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <cstring>

namespace
{
    constexpr std::size_t kEthernetHeaderSize = 14;
    constexpr std::size_t kLinuxSllHeaderSize = 16;

    struct SllHeader
    {
        uint16_t sll_pkttype;
        uint16_t sll_hatype;
        uint16_t sll_halen;
        uint8_t sll_addr[8];
        uint16_t sll_protocol;
    };
}

ParsedPacket PacketParser::parse(const pcap_pkthdr *header, const u_char *packet) const
{
    ParsedPacket parsed;
    if (!header || !packet || header->len < kLinuxSllHeaderSize)
    {
        return parsed;
    }

    uint16_t etherType = 0;
    std::size_t networkOffset = 0;
    if (!parseLinkLayer(packet, header->len, etherType, networkOffset))
    {
        return parsed;
    }

    if (!parseIPv4(packet + networkOffset, header->len - networkOffset, parsed, etherType))
    {
        return parsed;
    }

    parseTransportLayer(packet, header->len, networkOffset, parsed);
    detectApplicationLayer(parsed);

    parsed.valid = true;
    parsed.summary = parsed.sourceIp + ":" + std::to_string(parsed.sourcePort) + " -> " + parsed.destinationIp + ":" + std::to_string(parsed.destinationPort) + " [" + parsed.networkProtocol + "/" + parsed.transportProtocol + "]";
    return parsed;
}

bool PacketParser::parseEthernet(const u_char *packet, std::size_t length, uint16_t &etherType) const
{
    if (length < kEthernetHeaderSize)
    {
        return false;
    }

    const auto *ethernet = reinterpret_cast<const struct ether_header *>(packet);
    etherType = ntohs(ethernet->ether_type);
    return etherType == ETHERTYPE_IP;
}

bool PacketParser::parseLinuxSll(const u_char *packet, std::size_t length, uint16_t &etherType) const
{
    if (length < kLinuxSllHeaderSize)
    {
        return false;
    }

    const auto *sll = reinterpret_cast<const SllHeader *>(packet);
    etherType = ntohs(sll->sll_protocol);
    return etherType == ETHERTYPE_IP;
}

bool PacketParser::parseLinkLayer(const u_char *packet, std::size_t length, uint16_t &etherType, std::size_t &networkOffset) const
{
    // If the packet is Ethernet, parse from Ethernet header.
    if (length >= kEthernetHeaderSize)
    {
        const auto *eth = reinterpret_cast<const struct ether_header *>(packet);
        uint16_t type = ntohs(eth->ether_type);
        if (type == ETHERTYPE_IP)
        {
            etherType = type;
            networkOffset = kEthernetHeaderSize;
            return true;
        }
    }

    // If the packet is Linux cooked capture, parse from SLL header.
    if (length >= kLinuxSllHeaderSize)
    {
        const auto *sll = reinterpret_cast<const SllHeader *>(packet);
        uint16_t type = ntohs(sll->sll_protocol);
        if (type == ETHERTYPE_IP)
        {
            etherType = type;
            networkOffset = kLinuxSllHeaderSize;
            return true;
        }
    }

    return false;
}

bool PacketParser::parseIPv4(const u_char *packet, std::size_t length, ParsedPacket &parsed, uint16_t etherType) const
{
    if (etherType != ETHERTYPE_IP || length < sizeof(struct ip))
    {
        return false;
    }

    const auto *ipHeader = reinterpret_cast<const struct ip *>(packet);
    std::size_t ipHeaderLength = ipHeader->ip_hl * 4;
    if (ipHeaderLength < sizeof(struct ip) || length < ipHeaderLength)
    {
        return false;
    }

    char sourceBuffer[INET_ADDRSTRLEN] = {0};
    char destinationBuffer[INET_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET, &ipHeader->ip_src, sourceBuffer, sizeof(sourceBuffer));
    inet_ntop(AF_INET, &ipHeader->ip_dst, destinationBuffer, sizeof(destinationBuffer));

    parsed.sourceIp = sourceBuffer;
    parsed.destinationIp = destinationBuffer;
    parsed.networkProtocol = (ipHeader->ip_p == IPPROTO_TCP) ? "TCP" : (ipHeader->ip_p == IPPROTO_UDP) ? "UDP"
                                                                                                       : "OTHER";
    return true;
}

void PacketParser::parseTransportLayer(const u_char *packet, std::size_t length, std::size_t networkOffset, ParsedPacket &parsed) const
{
    if (parsed.networkProtocol != "TCP" && parsed.networkProtocol != "UDP")
    {
        return;
    }

    if (length < networkOffset + sizeof(struct ip))
    {
        return;
    }

    const auto *ipHeader = reinterpret_cast<const struct ip *>(packet + networkOffset);
    std::size_t ipHeaderLength = ipHeader->ip_hl * 4;
    std::size_t transportOffset = networkOffset + ipHeaderLength;
    if (length <= transportOffset)
    {
        return;
    }

    if (parsed.networkProtocol == "TCP")
    {
        if (length < transportOffset + sizeof(struct tcphdr))
        {
            return;
        }

        const auto *tcpHeader = reinterpret_cast<const struct tcphdr *>(packet + transportOffset);
        parsed.sourcePort = ntohs(tcpHeader->th_sport);
        parsed.destinationPort = ntohs(tcpHeader->th_dport);
        std::size_t tcpHeaderLength = tcpHeader->th_off * 4;
        std::size_t payloadOffset = transportOffset + tcpHeaderLength;
        if (length > payloadOffset)
        {
            parsed.payload.assign(reinterpret_cast<const char *>(packet + payloadOffset), length - payloadOffset);
        }
        parsed.transportProtocol = "TCP";
        return;
    }

    if (parsed.networkProtocol == "UDP")
    {
        if (length < transportOffset + sizeof(struct udphdr))
        {
            return;
        }

        const auto *udpHeader = reinterpret_cast<const struct udphdr *>(packet + transportOffset);
        parsed.sourcePort = ntohs(udpHeader->uh_sport);
        parsed.destinationPort = ntohs(udpHeader->uh_dport);
        std::size_t payloadOffset = transportOffset + sizeof(struct udphdr);
        if (length > payloadOffset)
        {
            parsed.payload.assign(reinterpret_cast<const char *>(packet + payloadOffset), length - payloadOffset);
        }
        parsed.transportProtocol = "UDP";
    }
}

void PacketParser::detectApplicationLayer(ParsedPacket &parsed) const
{
    const std::string payload = parsed.payload;
    const std::string lowerPayload = toLower(payload);
    bool isTlsHandshake = false;

    if (parsed.transportProtocol == "TCP" && payload.size() >= 6)
    {
        const auto *buffer = reinterpret_cast<const unsigned char *>(payload.data());
        if (buffer[0] == 0x16 && buffer[5] == 0x01)
        {
            isTlsHandshake = true;
        }
    }

    if (parsed.transportProtocol == "TCP" && (isTlsHandshake || parsed.destinationPort == 443 || parsed.sourcePort == 443))
    {
        parsed.applicationProtocol = "HTTPS";
        if (auto sni = SNIExtractor::extractTlsServerName(payload))
        {
            parsed.serverName = *sni;
        }
        return;
    }

    if (parsed.transportProtocol == "TCP")
    {
        if (lowerPayload.find("http/") != std::string::npos || lowerPayload.find("get ") != std::string::npos || lowerPayload.find("post ") != std::string::npos)
        {
            parsed.applicationProtocol = "HTTP";
            if (auto host = SNIExtractor::extractHttpHost(payload))
            {
                parsed.hostName = *host;
            }
            return;
        }

        if (parsed.sourcePort == 21 || parsed.destinationPort == 21 || lowerPayload.find("ftp") != std::string::npos)
        {
            parsed.applicationProtocol = "FTP";
            return;
        }
    }

    if (parsed.transportProtocol == "UDP")
    {
        if (parsed.sourcePort == 53 || parsed.destinationPort == 53 || lowerPayload.find("dns") != std::string::npos)
        {
            parsed.applicationProtocol = "DNS";
            return;
        }
    }

    parsed.applicationProtocol = "UNKNOWN";
}

std::string PacketParser::toLower(std::string value) const
{
    for (auto &ch : value)
    {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}
