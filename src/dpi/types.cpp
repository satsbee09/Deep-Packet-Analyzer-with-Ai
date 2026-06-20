#include "dpi/types.h"
#include <algorithm>

namespace dpi
{

    std::string appTypeToString(AppType type)
    {
        switch (type)
        {
        case AppType::HTTP:
            return "HTTP";
        case AppType::HTTPS:
            return "HTTPS";
        case AppType::DNS:
            return "DNS";
        case AppType::FTP:
            return "FTP";
        case AppType::YOUTUBE:
            return "YouTube";
        case AppType::FACEBOOK:
            return "Facebook";
        case AppType::GOOGLE:
            return "Google";
        case AppType::TWITTER:
            return "Twitter";
        case AppType::OTHER:
            return "Other";
        default:
            return "Unknown";
        }
    }

    AppType sniToAppType(const std::string &sni)
    {
        std::string lower = sni;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });

        if (lower.find("youtube") != std::string::npos)
        {
            return AppType::YOUTUBE;
        }
        if (lower.find("facebook") != std::string::npos)
        {
            return AppType::FACEBOOK;
        }
        if (lower.find("google") != std::string::npos)
        {
            return AppType::GOOGLE;
        }
        if (lower.find("twitter") != std::string::npos)
        {
            return AppType::TWITTER;
        }
        if (lower.find("ftp") != std::string::npos)
        {
            return AppType::FTP;
        }
        if (lower.find("dns") != std::string::npos)
        {
            return AppType::DNS;
        }
        if (lower.find("http") != std::string::npos)
        {
            return AppType::HTTP;
        }
        return AppType::UNKNOWN;
    }

} // namespace dpi
