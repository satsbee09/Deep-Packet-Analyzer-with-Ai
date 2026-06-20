#ifndef DPI_SNI_EXTRACTOR_H
#define DPI_SNI_EXTRACTOR_H

#include <optional>
#include <string>

class SNIExtractor
{
public:
    static std::optional<std::string> extractTlsServerName(const std::string &payload);
    static std::optional<std::string> extractHttpHost(const std::string &payload);
};

#endif // DPI_SNI_EXTRACTOR_H
