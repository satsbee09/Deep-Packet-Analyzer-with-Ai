#include "capture/pcap_writer.h"

PcapWriter::PcapWriter()
    : dumper_(nullptr) {}

PcapWriter::~PcapWriter()
{
    close();
}

bool PcapWriter::open(pcap_t *handle, const std::string &path)
{
    if (!handle)
    {
        return false;
    }
    dumper_ = pcap_dump_open(handle, path.c_str());
    return dumper_ != nullptr;
}

void PcapWriter::write(const pcap_pkthdr *header, const u_char *packet)
{
    if (dumper_)
    {
        pcap_dump(reinterpret_cast<u_char *>(dumper_), header, packet);
    }
}

void PcapWriter::close()
{
    if (dumper_)
    {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
    }
}

bool PcapWriter::isOpen() const
{
    return dumper_ != nullptr;
}
