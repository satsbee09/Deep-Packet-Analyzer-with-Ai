#ifndef DPI_PCAP_WRITER_H
#define DPI_PCAP_WRITER_H

#include <pcap.h>
#include <string>

class PcapWriter
{
public:
    PcapWriter();
    ~PcapWriter();

    bool open(pcap_t *handle, const std::string &path);
    void write(const pcap_pkthdr *header, const u_char *packet);
    void close();
    bool isOpen() const;

private:
    pcap_dumper_t *dumper_;
};

#endif // DPI_PCAP_WRITER_H
