#ifndef DPI_PACKET_PARSER_H
#define DPI_PACKET_PARSER_H

#include <pcap.h>
#include <cstdint>
#include <string>

struct ParsedPacket
{
    bool valid = false;
    std::string sourceIp;
    std::string destinationIp;
    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    std::string networkProtocol;
    std::string transportProtocol;
    std::string applicationProtocol;
    std::string hostName;
    std::string serverName;
    std::string payload;
    std::string summary;
};

class PacketParser
{
public:
    ParsedPacket parse(const pcap_pkthdr *header, const u_char *packet) const;

private:
    bool parseLinkLayer(const u_char *packet, std::size_t length, uint16_t &etherType, std::size_t &networkOffset) const;
    bool parseEthernet(const u_char *packet, std::size_t length, uint16_t &etherType) const;
    bool parseLinuxSll(const u_char *packet, std::size_t length, uint16_t &etherType) const;
    bool parseIPv4(const u_char *packet, std::size_t length, ParsedPacket &parsed, uint16_t etherType) const;
    void parseTransportLayer(const u_char *packet, std::size_t length, std::size_t networkOffset, ParsedPacket &parsed) const;
    void detectApplicationLayer(ParsedPacket &parsed) const;
    std::string toLower(std::string value) const;
};

#endif // DPI_PACKET_PARSER_H
