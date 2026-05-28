#include "LogEntry.h"
#include <iostream>
#include <sstream>

LogEntry::LogEntry()
    : timestamp(0), level(""), message(""), source(""), anomalyScore(0.0) {}

LogEntry::LogEntry(std::time_t ts, const std::string& lvl, const std::string& src, const std::string& msg)
    : timestamp(ts), level(lvl), message(msg), source(src), anomalyScore(0.0) {}

LogEntry::~LogEntry() {}

std::time_t LogEntry::getTimestamp() const {
    return timestamp;
}

const std::string& LogEntry::getLevel() const {
    return level;
}

const std::string& LogEntry::getMessage() const {
    return message;
}

const std::string& LogEntry::getSource() const {
    return source;
}

double LogEntry::getAnomalyScore() const {
    return anomalyScore;
}

void LogEntry::setLevel(const std::string& lvl) {
    level = lvl;
}

void LogEntry::setAnomalyScore(double score) {
    anomalyScore = score;
}

void LogEntry::display() const {
    std::cout << "[" << timestamp << "] " << level << " " << source << " " << message << " (score=" << anomalyScore << ")" << std::endl;
}

void LogEntry::saveToCSV(std::ofstream& ofs, const std::string& entryId) const {
    if (!ofs.good()) {
        return;
    }
    ofs << entryId << "," << timestamp << "," << level << "," << source << ",";
    std::string escaped = message;
    for (std::string::size_type i = 0; i < escaped.size(); ++i) {
        if (escaped[i] == '"') {
            escaped.insert(i, "\"");
            ++i;
        }
    }
    if (escaped.find(',') != std::string::npos || escaped.find('"') != std::string::npos) {
        ofs << '"' << escaped << '"';
    } else {
        ofs << escaped;
    }
    ofs << "," << anomalyScore << "\n";
}

static std::string toLowerCopy(const std::string& value) {
    std::string lower = value;
    for (std::string::size_type i = 0; i < lower.size(); ++i) {
        char c = lower[i];
        if (c >= 'A' && c <= 'Z') {
            lower[i] = c - 'A' + 'a';
        }
    }
    return lower;
}

static int containsToken(const std::string& haystack, const char* token) {
    std::string lower = toLowerCopy(haystack);
    std::string query = token;
    for (std::string::size_type i = 0; i < query.size(); ++i) {
        char c = query[i];
        if (c >= 'A' && c <= 'Z') {
            query[i] = c - 'A' + 'a';
        }
    }
    return lower.find(query) != std::string::npos;
}

InfoLogEntry::InfoLogEntry(std::time_t ts, const std::string& src, const std::string& msg)
    : LogEntry(ts, "INFO", src, msg) {
    anomalyScore = calculateAnomalyScore();
}

InfoLogEntry::~InfoLogEntry() {}

std::string InfoLogEntry::getType() const {
    return "INFO";
}

double InfoLogEntry::calculateAnomalyScore() {
    anomalyScore = 0.0;
    return anomalyScore;
}

void InfoLogEntry::display() const {
    std::cout << "[INFO] " << source << " - " << message << " (score=" << anomalyScore << ")" << std::endl;
}

WarningLogEntry::WarningLogEntry(std::time_t ts, const std::string& src, const std::string& msg)
    : LogEntry(ts, "WARNING", src, msg) {
    anomalyScore = calculateAnomalyScore();
}

WarningLogEntry::~WarningLogEntry() {}

std::string WarningLogEntry::getType() const {
    return "WARNING";
}

double WarningLogEntry::calculateAnomalyScore() {
    double score = 0.3;
    if (containsToken(message, "memory") || containsToken(message, "disk") || containsToken(message, "slow")) {
        score += 0.15;
    }
    if (containsToken(message, "failed") || containsToken(message, "error")) {
        score += 0.15;
    }
    if (score > 0.85) {
        score = 0.85;
    }
    anomalyScore = score;
    return anomalyScore;
}

void WarningLogEntry::display() const {
    std::cout << "[WARNING] " << source << " - " << message << " (score=" << anomalyScore << ")" << std::endl;
}

ErrorLogEntry::ErrorLogEntry(std::time_t ts, const std::string& src, const std::string& msg)
    : LogEntry(ts, "ERROR", src, msg) {
    anomalyScore = calculateAnomalyScore();
}

ErrorLogEntry::~ErrorLogEntry() {}

std::string ErrorLogEntry::getType() const {
    return "ERROR";
}

double ErrorLogEntry::calculateAnomalyScore() {
    if (containsToken(message, "sql injection")) {
        anomalyScore = 0.98;
        return anomalyScore;
    }
    if (containsToken(message, "exception")) {
        anomalyScore = 0.92;
        return anomalyScore;
    }
    if (containsToken(message, "timeout") || containsToken(message, "failed")) {
        anomalyScore = 0.85;
        return anomalyScore;
    }
    if (containsToken(message, "unauthorized") || containsToken(message, "denied")) {
        anomalyScore = 0.80;
        return anomalyScore;
    }
    anomalyScore = 0.70;
    return anomalyScore;
}

void ErrorLogEntry::display() const {
    std::cout << "[ERROR] " << source << " - " << message << " (score=" << anomalyScore << ")" << std::endl;
}

SecurityLogEntry::SecurityLogEntry(std::time_t ts, const std::string& src, const std::string& msg)
    : LogEntry(ts, "SECURITY", src, msg) {
    anomalyScore = calculateAnomalyScore();
}

SecurityLogEntry::~SecurityLogEntry() {}

std::string SecurityLogEntry::getType() const {
    return "SECURITY";
}

double SecurityLogEntry::calculateAnomalyScore() {
    double score = 0.9;
    if (containsToken(message, "failed login") || containsToken(message, "suspicious") || containsToken(message, "injection")) {
        score += 0.08;
    }
    if (containsToken(message, "unauthorized") || containsToken(message, "access denied") || containsToken(message, "breach")) {
        score += 0.05;
    }
    if (score > 0.99) {
        score = 0.99;
    }
    anomalyScore = score;
    return anomalyScore;
}

void SecurityLogEntry::display() const {
    std::cout << "[SECURITY] " << source << " - " << message << " (score=" << anomalyScore << ")" << std::endl;
}
