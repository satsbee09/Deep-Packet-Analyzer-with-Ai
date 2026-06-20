#include "capture/pcap_reader.h"
#include <pcap.h>

PcapReader::PcapReader()
    : handle_(nullptr), dataLinkType_(DLT_EN10MB) {}

PcapReader::~PcapReader()
{
    close();
}

bool PcapReader::open(const std::string &path)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_offline(path.c_str(), errbuf);
    live_ = false;
    if (handle_)
    {
        dataLinkType_ = pcap_datalink(handle_);
    }
    return handle_ != nullptr;
}

bool PcapReader::openLive(const std::string &interfaceName)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    // snapshot length 65535, promiscuous mode, 1000ms timeout
    handle_ = pcap_open_live(interfaceName.c_str(), 65535, 1, 1000, errbuf);
    if (handle_)
    {
        live_ = true;
        dataLinkType_ = pcap_datalink(handle_);
        return true;
    }
    return false;
}

bool PcapReader::readNextPacket(RawPacket &packet)
{
    if (!handle_)
    {
        return false;
    }

    const u_char *data = nullptr;
    struct pcap_pkthdr *headerPtr = nullptr;
    int result = pcap_next_ex(handle_, &headerPtr, &data);
    if (result <= 0 || !data)
    {
        return false;
    }

    packet.header = *headerPtr;
    packet.data.assign(data, data + packet.header.caplen);
    return true;
}

void PcapReader::close()
{
    if (handle_)
    {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PcapReader::isOpen() const
{
    return handle_ != nullptr;
}

pcap_t *PcapReader::handle() const
{
    return handle_;
}

int PcapReader::dataLinkType() const
{
    return dataLinkType_;
}

bool PcapReader::isLive() const
{
    return live_;
}
