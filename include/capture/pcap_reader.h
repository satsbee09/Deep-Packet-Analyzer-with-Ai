#ifndef DPI_PCAP_READER_H
#define DPI_PCAP_READER_H

#include <pcap.h>
#include <string>
#include <vector>

struct RawPacket
{
    pcap_pkthdr header;
    std::vector<u_char> data;
};

class PcapReader
{
public:
    PcapReader();
    ~PcapReader();

    bool open(const std::string &path);
    bool openLive(const std::string &interfaceName);
    bool readNextPacket(RawPacket &packet);
    void close();
    bool isOpen() const;
    pcap_t *handle() const;
    int dataLinkType() const;
    // whether the reader was opened for live capture
    bool isLive() const;

private:
    pcap_t *handle_;
    bool live_ = false;
    int dataLinkType_ = DLT_EN10MB;
};

#endif // DPI_PCAP_READER_H
