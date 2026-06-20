#include "logger/logger.h"
#include <cstdio>
#include <ctime>

Logger::Logger(std::string filePath)
    : filePath_(std::move(filePath)), enabled_(true), file_(nullptr)
{
    file_ = std::fopen(filePath_.c_str(), "a");
}

Logger::~Logger()
{
    if (file_)
    {
        std::fclose(file_);
    }
}

bool Logger::isEnabled() const
{
    return enabled_;
}

void Logger::enable(bool enabled)
{
    enabled_ = enabled;
}

void Logger::log(const std::string &message)
{
    if (!enabled_ || !file_)
    {
        return;
    }

    std::time_t now = std::time(nullptr);
    char timeBuffer[64] = {0};
    std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    std::fprintf(file_, "%s %s\n", timeBuffer, message.c_str());
    std::fflush(file_);
}
