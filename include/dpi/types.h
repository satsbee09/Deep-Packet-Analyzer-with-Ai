#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>

namespace dpi
{

    enum class AppType
    {
        UNKNOWN,
        HTTP,
        HTTPS,
        DNS,
        FTP,
        YOUTUBE,
        FACEBOOK,
        GOOGLE,
        TWITTER,
        OTHER
    };

    struct FiveTuple
    {
        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t protocol = 0;

        bool operator==(const FiveTuple &other) const noexcept = default;
    };

    struct FiveTupleHash
    {
        std::size_t operator()(const FiveTuple &key) const noexcept
        {
            const std::size_t h1 = std::hash<uint32_t>{}(key.src_ip);
            const std::size_t h2 = std::hash<uint32_t>{}(key.dst_ip);
            const std::size_t h3 = std::hash<uint16_t>{}(key.src_port);
            const std::size_t h4 = std::hash<uint16_t>{}(key.dst_port);
            const std::size_t h5 = std::hash<uint8_t>{}(key.protocol);
            return (((((h1 * 31u) ^ h2) * 31u) ^ h3) * 31u ^ h4) * 31u ^ h5;
        }
    };

    std::string appTypeToString(AppType type);
    AppType sniToAppType(const std::string &sni);

} // namespace dpi

#endif // DPI_TYPES_H
