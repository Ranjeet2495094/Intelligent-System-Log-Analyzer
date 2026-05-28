#ifndef LOGPARSER_H
#define LOGPARSER_H

#include <string>
#include <vector>
#include "LogEntry.h"

class LogParser {
public:
    LogParser();
    virtual ~LogParser();

    bool parseFile(const std::string& filename, std::vector<LogEntry*>& entries, std::string& errorMessage);
    bool loadParsedEntries(const std::string& filename, std::vector<LogEntry*>& entries, std::string& errorMessage);
    bool saveParsedEntries(const std::string& filename, const std::vector<LogEntry*>& entries, std::string& errorMessage);
    LogEntry* parseLine(const std::string& line, std::string& errorMessage);
    static bool parseTimestamp(const std::string& token, std::time_t& output);
};

#endif // LOGPARSER_H
