#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "parser/packet_parser.h"
#include "rules/rule_engine.h"
#include "detection/threat_detector.h"
#include "logger/logger.h"
#include "dpi/types.h"
#include <string>
#include <vector>

struct DpiResult
{
    bool valid = false;
    bool blocked = false;
    std::vector<std::string> reasons;
    std::string summary;
    dpi::AppType appType = dpi::AppType::UNKNOWN;
};

class DpiEngine
{
public:
    DpiEngine();
    bool loadRules(const std::string &ruleFile);
    DpiResult inspect(const pcap_pkthdr *header, const u_char *packet);

private:
    PacketParser parser_;
    RuleEngine ruleEngine_;
    ThreatDetector detector_;
};

#endif // DPI_ENGINE_H
