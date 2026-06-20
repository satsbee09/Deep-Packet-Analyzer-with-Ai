#include "parser/sni_extractor.h"
#include <cstring>
#include <cstdint>
#include <optional>
#include <string>

static uint16_t readUint16BE(const uint8_t *data)
{
    return static_cast<uint16_t>(data[0]) << 8 | static_cast<uint16_t>(data[1]);
}

std::optional<std::string> SNIExtractor::extractTlsServerName(const std::string &payload)
{
    if (payload.size() < 5 || static_cast<uint8_t>(payload[0]) != 0x16)
    {
        return std::nullopt;
    }

    const uint8_t *buffer = reinterpret_cast<const uint8_t *>(payload.data());
    if (payload.size() < 6 || buffer[5] != 0x01)
    {
        return std::nullopt;
    }

    size_t offset = 43;
    if (offset >= payload.size())
    {
        return std::nullopt;
    }

    uint8_t sessionLen = buffer[offset];
    offset += 1 + sessionLen;
    if (offset + 2 > payload.size())
    {
        return std::nullopt;
    }

    uint16_t cipherLen = readUint16BE(buffer + offset);
    offset += 2 + cipherLen;
    if (offset + 1 > payload.size())
    {
        return std::nullopt;
    }

    uint8_t compressionLen = buffer[offset];
    offset += 1 + compressionLen;
    if (offset + 2 > payload.size())
    {
        return std::nullopt;
    }

    uint16_t extensionsLen = readUint16BE(buffer + offset);
    offset += 2;
    if (offset + extensionsLen > payload.size())
    {
        return std::nullopt;
    }

    size_t end = offset + extensionsLen;
    while (offset + 4 <= end)
    {
        uint16_t extType = readUint16BE(buffer + offset);
        uint16_t extLen = readUint16BE(buffer + offset + 2);
        offset += 4;
        if (offset + extLen > end)
        {
            return std::nullopt;
        }

        if (extType == 0x0000 && offset + 2 <= end)
        {
            uint16_t sniListLen = readUint16BE(buffer + offset);
            offset += 2;
            if (offset + sniListLen > end)
            {
                return std::nullopt;
            }

            if (offset + 3 > end)
            {
                return std::nullopt;
            }

            uint8_t sniType = buffer[offset];
            uint16_t sniLen = readUint16BE(buffer + offset + 1);
            offset += 3;
            if (sniType != 0x00 || offset + sniLen > end)
            {
                return std::nullopt;
            }

            return std::string(reinterpret_cast<const char *>(buffer + offset), sniLen);
        }

        offset += extLen;
    }

    return std::nullopt;
}

std::optional<std::string> SNIExtractor::extractHttpHost(const std::string &payload)
{
    const std::string lowerPayload(payload);
    auto hostPos = lowerPayload.find("host:");
    if (hostPos == std::string::npos)
    {
        return std::nullopt;
    }

    hostPos += 5;
    while (hostPos < payload.size() && (payload[hostPos] == ' ' || payload[hostPos] == '\t'))
    {
        ++hostPos;
    }

    size_t endPos = payload.find("\r\n", hostPos);
    if (endPos == std::string::npos)
    {
        endPos = payload.find('\n', hostPos);
    }

    if (endPos == std::string::npos)
    {
        return std::nullopt;
    }

    return payload.substr(hostPos, endPos - hostPos);
}
