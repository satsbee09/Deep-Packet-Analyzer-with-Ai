#ifndef DPI_CAPTURE_MANAGER_H
#define DPI_CAPTURE_MANAGER_H

#include <pcap.h>
#include <functional>
#include <string>

class CaptureManager
{
public:
    using PacketHandler = std::function<void(const pcap_pkthdr *, const u_char *)>;

    CaptureManager();
    ~CaptureManager();

    bool openLive(const std::string &interfaceName, bool promiscuous);
    bool openOffline(const std::string &pcapPath);
    bool startCapture(int packetLimit = 0);
    void stopCapture();
    void setHandler(PacketHandler handler);

private:
    pcap_t *handle_;
    PacketHandler packetHandler_;
    bool running_;
    static void packetCallback(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet);
};

#endif // DPI_CAPTURE_MANAGER_H
