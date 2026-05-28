#include "LogParser.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <iostream>

LogParser::LogParser() {}
LogParser::~LogParser() {}

bool LogParser::parseTimestamp(const std::string& token, std::time_t& output) {
    struct std::tm tmValue;
    std::memset(&tmValue, 0, sizeof(tmValue));
    int year, month, day, hour, minute, second;
    if (std::sscanf(token.c_str(), "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second) != 6) {
        return false;
    }
    tmValue.tm_year = year - 1900;
    tmValue.tm_mon = month - 1;
    tmValue.tm_mday = day;
    tmValue.tm_hour = hour;
    tmValue.tm_min = minute;
    tmValue.tm_sec = second;
    tmValue.tm_isdst = -1;
    output = std::mktime(&tmValue);
    return output != -1;
}

bool LogParser::parseFile(const std::string& filename, std::vector<LogEntry*>& entries, std::string& errorMessage) {
    std::ifstream ifs(filename.c_str());
    if (!ifs.is_open()) {
        errorMessage = "Could not open log file: " + filename;
        return false;
    }
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) {
            continue;
        }
        std::string lineError;
        LogEntry* entry = parseLine(line, lineError);
        if (entry != NULL) {
            entries.push_back(entry);
        }
    }
    return true;
}

LogEntry* LogParser::parseLine(const std::string& line, std::string& errorMessage) {
    std::string trimmed = line;
    if (trimmed.empty()) {
        errorMessage = "Empty line.";
        return NULL;
    }
    std::time_t timestamp = 0;
    std::string level;
    std::string source;
    std::string message;

    if (trimmed[0] == '[') {
        std::size_t closeBracket = trimmed.find(']');
        if (closeBracket == std::string::npos) {
            errorMessage = "Malformed timestamp bracket.";
            return NULL;
        }
        std::string timestampToken = trimmed.substr(1, closeBracket - 1);
        if (!parseTimestamp(timestampToken, timestamp)) {
            errorMessage = "Invalid timestamp format.";
            return NULL;
        }
        std::size_t current = closeBracket + 1;
        while (current < trimmed.size() && trimmed[current] == ' ') {
            ++current;
        }
        std::size_t nextSpace = trimmed.find(' ', current);
        if (nextSpace == std::string::npos) {
            errorMessage = "Missing log level.";
            return NULL;
        }
        level = trimmed.substr(current, nextSpace - current);
        current = nextSpace + 1;
        nextSpace = trimmed.find(' ', current);
        if (nextSpace == std::string::npos) {
            errorMessage = "Missing source or message.";
            return NULL;
        }
        source = trimmed.substr(current, nextSpace - current);
        message = trimmed.substr(nextSpace + 1);
    } else {
        std::istringstream iss(trimmed);
        std::string timestampToken;
        if (!(iss >> timestampToken)) {
            errorMessage = "Malformed line without timestamp.";
            return NULL;
        }
        std::string nextToken;
        if (!(iss >> nextToken)) {
            errorMessage = "Malformed line without level.";
            return NULL;
        }
        level = nextToken;
        if (!(iss >> source)) {
            errorMessage = "Malformed line without source.";
            return NULL;
        }
        std::getline(iss, message);
        if (!message.empty() && message[0] == ' ') {
            message.erase(0, 1);
        }
        std::string combined = timestampToken + " " + nextToken;
        if (!parseTimestamp(combined, timestamp)) {
            errorMessage = "Invalid fallback timestamp.";
            return NULL;
        }
    }

    if (level.empty() || source.empty() || message.empty()) {
        errorMessage = "Incomplete log entry.";
        return NULL;
    }

    std::string normalizedLevel = level;
    for (std::string::size_type i = 0; i < normalizedLevel.size(); ++i) {
        char c = normalizedLevel[i];
        if (c >= 'a' && c <= 'z') {
            normalizedLevel[i] = c - 'a' + 'A';
        }
    }

    LogEntry* entry = NULL;
    if (normalizedLevel == "INFO") {
        entry = new InfoLogEntry(timestamp, source, message);
    } else if (normalizedLevel == "WARNING" || normalizedLevel == "WARN") {
        entry = new WarningLogEntry(timestamp, source, message);
    } else if (normalizedLevel == "ERROR") {
        entry = new ErrorLogEntry(timestamp, source, message);
    } else if (normalizedLevel == "SECURITY") {
        entry = new SecurityLogEntry(timestamp, source, message);
    } else {
        entry = new InfoLogEntry(timestamp, source, message);
        entry->setLevel(normalizedLevel);
    }
    return entry;
}

bool LogParser::saveParsedEntries(const std::string& filename, const std::vector<LogEntry*>& entries, std::string& errorMessage) {
    std::ofstream ofs(filename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Could not open output file: " + filename;
        return false;
    }
    ofs << "entryID,timestamp,level,source,message,anomalyScore\n";
    for (std::size_t i = 0; i < entries.size(); ++i) {
        std::string entryId;
        std::ostringstream idStream;
        idStream << "E" << (1000 + static_cast<int>(i));
        entryId = idStream.str();
        entries[i]->saveToCSV(ofs, entryId);
    }
    return true;
}

bool LogParser::loadParsedEntries(const std::string& filename, std::vector<LogEntry*>& entries, std::string& errorMessage) {
    std::ifstream ifs(filename.c_str());
    if (!ifs.is_open()) {
        errorMessage = "Could not open parsed entries file: " + filename;
        return false;
    }
    std::string line;
    if (!std::getline(ifs, line)) {
        return false;
    }

    while (std::getline(ifs, line)) {
        if (line.empty()) {
            continue;
        }
        std::size_t a = line.find(',');
        if (a == std::string::npos) {
            continue;
        }
        std::size_t b = line.find(',', a + 1);
        if (b == std::string::npos) {
            continue;
        }
        std::size_t c = line.find(',', b + 1);
        if (c == std::string::npos) {
            continue;
        }
        std::size_t d = line.find(',', c + 1);
        if (d == std::string::npos) {
            continue;
        }
        std::size_t e = line.rfind(',');
        if (e == std::string::npos || e == d) {
            continue;
        }
        std::string timestampToken = line.substr(a + 1, b - a - 1);
        std::string levelToken = line.substr(b + 1, c - b - 1);
        std::string sourceToken = line.substr(c + 1, d - c - 1);
        std::string messageToken = line.substr(d + 1, e - d - 1);
        std::string scoreToken = line.substr(e + 1);
        if (!messageToken.empty() && messageToken[0] == '"' && messageToken[messageToken.size() - 1] == '"') {
            messageToken = messageToken.substr(1, messageToken.size() - 2);
        }
        std::time_t ts = 0;
        std::istringstream tsStream(timestampToken);
        tsStream >> ts;
        double score = 0.0;
        std::istringstream scoreStream(scoreToken);
        scoreStream >> score;

        std::string normalizedLevel = levelToken;
        for (std::string::size_type i = 0; i < normalizedLevel.size(); ++i) {
            char cChar = normalizedLevel[i];
            if (cChar >= 'a' && cChar <= 'z') {
                normalizedLevel[i] = cChar - 'a' + 'A';
            }
        }

        LogEntry* entry = NULL;
        if (normalizedLevel == "INFO") {
            entry = new InfoLogEntry(ts, sourceToken, messageToken);
        } else if (normalizedLevel == "WARNING") {
            entry = new WarningLogEntry(ts, sourceToken, messageToken);
        } else if (normalizedLevel == "ERROR") {
            entry = new ErrorLogEntry(ts, sourceToken, messageToken);
        } else if (normalizedLevel == "SECURITY") {
            entry = new SecurityLogEntry(ts, sourceToken, messageToken);
        } else {
            entry = new InfoLogEntry(ts, sourceToken, messageToken);
            entry->setLevel(normalizedLevel);
        }
        entry->setAnomalyScore(score);
        entries.push_back(entry);
    }
    return true;
}
