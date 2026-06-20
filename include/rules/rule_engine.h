#ifndef DPI_RULE_ENGINE_H
#define DPI_RULE_ENGINE_H

#include <pcap.h>
#include <filesystem>
#include <regex>
#include <string>
#include <vector>

class RuleEngine
{
public:
    bool loadRules(const std::string &ruleFilePath);
    bool reloadIfModified();
    std::vector<std::string> match(const std::string &input) const;
    bool isLoaded() const;

private:
    struct Rule
    {
        std::string name;
        std::string pattern;
        bool useRegex = false;
        std::regex compiled;
    };

    bool loadFromFile();
    static std::string trim(const std::string &value);
    static std::pair<std::string, std::string> splitRuleLine(const std::string &line);

    std::string ruleFilePath_;
    std::filesystem::file_time_type lastWriteTime_;
    std::vector<Rule> rules_;
};

#endif // DPI_RULE_ENGINE_H
