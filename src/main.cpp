#include "capture/pcap_reader.h"
#include "capture/pcap_writer.h"
#include "dpi/dpi_engine.h"
#include "logger/logger.h"
#include <filesystem>
#include <iostream>
#include <string>

static void printUsage(const std::string &programName)
{
    std::cout << "Usage: " << programName
              << " --offline <pcap-file> | --live <interface> [--rules <rule-file>] [--log <log-file>] [--no-log]" << std::endl;
}

int main(int argc, char *argv[])
{
    std::string offlinePcap;
    std::string liveInterface;
    std::string ruleFile = "config/rules.txt";
    std::string logFile = "logs/traffic.log";
    bool enableLogging = true;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--offline" && i + 1 < argc)
        {
            offlinePcap = argv[++i];
        }
        else if (arg == "--rules" && i + 1 < argc)
        {
            ruleFile = argv[++i];
        }
        else if (arg == "--log" && i + 1 < argc)
        {
            logFile = argv[++i];
        }
        else if (arg == "--live" && i + 1 < argc)
        {
            liveInterface = argv[++i];
        }
        else if (arg == "--no-log")
        {
            enableLogging = false;
        }
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(argv[0]);
            return 0;
        }
        else
        {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    if (offlinePcap.empty() && liveInterface.empty())
    {
        std::cerr << "Either --offline <pcap-file> or --live <interface> is required." << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    if (enableLogging)
    {
        std::filesystem::path logPath(logFile);
        if (logPath.has_parent_path())
        {
            std::filesystem::create_directories(logPath.parent_path());
        }
    }

    DpiEngine dpiEngine;
    if (!dpiEngine.loadRules(ruleFile))
    {
        std::cerr << "Failed to load rules from " << ruleFile << std::endl;
        return 1;
    }

    Logger logger(logFile);
    logger.enable(enableLogging);

    PcapReader reader;
    if (!liveInterface.empty())
    {
        if (!reader.openLive(liveInterface))
        {
            std::cerr << "Failed to open live interface: " << liveInterface << std::endl;
            return 1;
        }
    }
    else
    {
        if (!reader.open(offlinePcap))
        {
            std::cerr << "Failed to open input PCAP: " << offlinePcap << std::endl;
            return 1;
        }
    }

    PcapWriter writer;
    if (!writer.open(reader.handle(), "output_filtered.pcap"))
    {
        std::cerr << "Failed to open output PCAP file." << std::endl;
        return 1;
    }

    RawPacket raw;
    while (reader.readNextPacket(raw))
    {
        auto result = dpiEngine.inspect(&raw.header, raw.data.data());
        if (!result.valid)
        {
            continue;
        }

        if (result.blocked)
        {
            std::string reasonString;
            for (const auto &reason : result.reasons)
            {
                if (!reasonString.empty())
                {
                    reasonString += "; ";
                }
                reasonString += reason;
            }
            logger.log("BLOCKED: " + result.summary + " reasons=" + reasonString);
            std::cout << "BLOCKED: " << result.summary << " reasons=" << reasonString << std::endl;
        }
        else
        {
            writer.write(&raw.header, raw.data.data());
        }
    }

    reader.close();
    writer.close();
    std::cout << "Processing complete." << std::endl;
    return 0;
}
