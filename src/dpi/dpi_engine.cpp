#include "dpi/dpi_engine.h"
#include "parser/sni_extractor.h"
#include <algorithm>
#include <sstream>

DpiEngine::DpiEngine() = default;

bool DpiEngine::loadRules(const std::string &ruleFile)
{
    return ruleEngine_.loadRules(ruleFile);
}

DpiResult DpiEngine::inspect(const pcap_pkthdr *header, const u_char *packet)
{
    DpiResult result;
    auto parsed = parser_.parse(header, packet);
    if (!parsed.valid)
    {
        return result;
    }

    result.summary = parsed.summary;
    result.appType = dpi::AppType::UNKNOWN;

    if (!parsed.payload.empty())
    {
        if (parsed.applicationProtocol == "HTTPS")
        {
            result.reasons.push_back("HTTPS");
            if (!parsed.serverName.empty())
            {
                result.reasons.push_back("SNI=" + parsed.serverName);
                result.appType = dpi::sniToAppType(parsed.serverName);
            }
            else
            {
                result.appType = dpi::AppType::HTTPS;
            }
        }

        if (parsed.applicationProtocol == "HTTP")
        {
            result.reasons.push_back("HTTP");
            if (!parsed.hostName.empty())
            {
                result.reasons.push_back("Host=" + parsed.hostName);
                result.appType = dpi::sniToAppType(parsed.hostName);
            }
        }

        if (result.appType == dpi::AppType::UNKNOWN && parsed.applicationProtocol != "UNKNOWN")
        {
            if (parsed.applicationProtocol == "HTTP")
            {
                result.appType = dpi::AppType::HTTP;
            }
            else if (parsed.applicationProtocol == "HTTPS")
            {
                result.appType = dpi::AppType::HTTPS;
            }
        }
    }

    auto threats = detector_.analyze(parsed.payload);
    for (const auto &threat : threats)
    {
        result.reasons.push_back(threat);
    }

    std::string ruleInput = parsed.payload;
    if (!parsed.serverName.empty())
    {
        ruleInput += " ";
        ruleInput += parsed.serverName;
    }
    if (!parsed.hostName.empty())
    {
        ruleInput += " ";
        ruleInput += parsed.hostName;
    }

    auto ruleMatches = ruleEngine_.match(ruleInput);
    for (const auto &match : ruleMatches)
    {
        result.reasons.push_back("Rule=" + match);
    }

    if (!threats.empty() || !ruleMatches.empty())
    {
        result.blocked = true;
    }

    result.valid = true;
    return result;
}
