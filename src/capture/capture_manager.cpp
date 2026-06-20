#include "capture/capture_manager.h"
#include <iostream>

CaptureManager::CaptureManager()
    : handle_(nullptr), running_(false) {}

CaptureManager::~CaptureManager()
{
    stopCapture();
    if (handle_)
    {
        pcap_close(handle_);
    }
}

bool CaptureManager::openLive(const std::string &interfaceName, bool promiscuous)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_live(interfaceName.c_str(), 65535, promiscuous ? 1 : 0, 1000, errbuf);
    if (!handle_)
    {
        std::cerr << "Failed to open live interface '" << interfaceName << "': " << errbuf << '\n';
        return false;
    }
    return true;
}

bool CaptureManager::openOffline(const std::string &pcapPath)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    handle_ = pcap_open_offline(pcapPath.c_str(), errbuf);
    if (!handle_)
    {
        std::cerr << "Failed to open PCAP file '" << pcapPath << "': " << errbuf << '\n';
        return false;
    }
    return true;
}

bool CaptureManager::startCapture(int packetLimit)
{
    if (!handle_)
    {
        std::cerr << "Capture handle is not initialized.\n";
        return false;
    }

    if (!packetHandler_)
    {
        std::cerr << "Packet handler is not set.\n";
        return false;
    }

    running_ = true;
    int result = pcap_loop(handle_, packetLimit, packetCallback, reinterpret_cast<u_char *>(this));
    if (result == -1)
    {
        std::cerr << "Capture error: " << pcap_geterr(handle_) << '\n';
        return false;
    }

    running_ = false;
    return true;
}

void CaptureManager::stopCapture()
{
    if (handle_ && running_)
    {
        pcap_breakloop(handle_);
        running_ = false;
    }
}

void CaptureManager::setHandler(PacketHandler handler)
{
    packetHandler_ = std::move(handler);
}

void CaptureManager::packetCallback(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (!userData)
    {
        return;
    }

    auto *self = reinterpret_cast<CaptureManager *>(userData);
    if (self->packetHandler_)
    {
        self->packetHandler_(header, packet);
    }
}
