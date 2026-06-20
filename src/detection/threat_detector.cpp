#include "detection/threat_detector.h"
#include <algorithm>

std::vector<std::string> ThreatDetector::analyze(const std::string &payload) const
{
    std::vector<std::string> threats;
    std::string lowercasePayload = payload;
    std::transform(lowercasePayload.begin(), lowercasePayload.end(), lowercasePayload.begin(), [](unsigned char c)
                   { return static_cast<char>(std::tolower(c)); });

    if (lowercasePayload.find("' or 1=1") != std::string::npos || lowercasePayload.find("or 1=1") != std::string::npos)
    {
        threats.push_back("SQL Injection");
    }
    if (lowercasePayload.find("<script>") != std::string::npos)
    {
        threats.push_back("Cross Site Scripting");
    }
    if (lowercasePayload.find("http://") != std::string::npos || lowercasePayload.find("https://") != std::string::npos)
    {
        threats.push_back("Suspicious URL");
    }
    return threats;
}
