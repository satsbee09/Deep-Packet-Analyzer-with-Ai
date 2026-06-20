#include "rules/rule_engine.h"
#include <fstream>
#include <iostream>
#include <sstream>

namespace
{
    constexpr char RuleSeparator = ':';
}

bool RuleEngine::loadRules(const std::string &ruleFilePath)
{
    ruleFilePath_ = ruleFilePath;
    return loadFromFile();
}

bool RuleEngine::reloadIfModified()
{
    if (ruleFilePath_.empty())
    {
        return false;
    }

    std::error_code ec;
    auto currentTime = std::filesystem::last_write_time(ruleFilePath_, ec);
    if (ec)
    {
        return false;
    }

    if (currentTime != lastWriteTime_)
    {
        return loadFromFile();
    }
    return true;
}

std::vector<std::string> RuleEngine::match(const std::string &input) const
{
    std::vector<std::string> matches;
    for (const auto &rule : rules_)
    {
        if (rule.useRegex)
        {
            if (std::regex_search(input, rule.compiled))
            {
                matches.push_back(rule.name);
            }
        }
        else
        {
            if (input.find(rule.pattern) != std::string::npos)
            {
                matches.push_back(rule.name);
            }
        }
    }
    return matches;
}

bool RuleEngine::isLoaded() const
{
    return !rules_.empty();
}

bool RuleEngine::loadFromFile()
{
    rules_.clear();
    std::ifstream file(ruleFilePath_);
    if (!file)
    {
        std::cerr << "Failed to open rule file: " << ruleFilePath_ << '\n';
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        line = trim(line);
        if (line.empty() || line.rfind("#", 0) == 0)
        {
            continue;
        }

        auto [name, pattern] = splitRuleLine(line);
        if (name.empty() || pattern.empty())
        {
            continue;
        }

        Rule rule;
        rule.name = name;
        rule.pattern = pattern;
        rule.useRegex = (pattern.rfind("regex:", 0) == 0);
        if (rule.useRegex)
        {
            rule.pattern = pattern.substr(6);
            try
            {
                rule.compiled = std::regex(rule.pattern, std::regex::icase);
            }
            catch (const std::regex_error &ex)
            {
                std::cerr << "Invalid regex rule '" << name << "': " << ex.what() << '\n';
                continue;
            }
        }
        rules_.push_back(std::move(rule));
    }

    std::error_code ec;
    lastWriteTime_ = std::filesystem::last_write_time(ruleFilePath_, ec);
    return !rules_.empty();
}

std::string RuleEngine::trim(const std::string &value)
{
    const auto whitespace = " \t\n\r";
    const auto left = value.find_first_not_of(whitespace);
    if (left == std::string::npos)
    {
        return "";
    }
    const auto right = value.find_last_not_of(whitespace);
    return value.substr(left, right - left + 1);
}

std::pair<std::string, std::string> RuleEngine::splitRuleLine(const std::string &line)
{
    const auto pos = line.find(RuleSeparator);
    if (pos == std::string::npos)
    {
        return {"", ""};
    }

    std::string name = trim(line.substr(0, pos));
    std::string value = trim(line.substr(pos + 1));
    return {name, value};
}
