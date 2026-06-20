#ifndef DPI_LOGGER_H
#define DPI_LOGGER_H

#include <string>

class Logger
{
public:
    explicit Logger(std::string filePath);
    ~Logger();

    bool isEnabled() const;
    void enable(bool enabled);
    void log(const std::string &message);

private:
    std::string filePath_;
    bool enabled_;
    FILE *file_;
};

#endif // DPI_LOGGER_H
