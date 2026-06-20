#ifndef DPI_THREAT_DETECTOR_H
#define DPI_THREAT_DETECTOR_H

#include <string>
#include <vector>

class ThreatDetector
{
public:
    std::vector<std::string> analyze(const std::string &payload) const;
};

#endif // DPI_THREAT_DETECTOR_H
