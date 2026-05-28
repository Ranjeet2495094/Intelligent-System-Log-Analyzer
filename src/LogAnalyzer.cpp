#include "LogAnalyzer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <functional>
#include <cmath>

static bool compareByTimestamp(LogEntry* left, LogEntry* right) {
    if (left == NULL || right == NULL) {
        return left == NULL && right != NULL;
    }
    return left->getTimestamp() < right->getTimestamp();
}

LogAnalyzer::LogAnalyzer(std::vector<LogEntry*>* allEntries)
    : entries(allEntries) {}

LogAnalyzer::~LogAnalyzer() {}

void LogAnalyzer::analyzeFrequencies() {
    levelCount.clear();
    sourceCount.clear();
    keywordCount.clear();
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        std::string level = entry->getLevel();
        if (level.empty()) {
            level = entry->getType();
        }
        ++levelCount[level];
        ++sourceCount[entry->getSource()];
        const std::string& msg = entry->getMessage();
        std::istringstream iss(msg);
        std::string token;
        while (iss >> token) {
            if (token.size() > 3) {
                ++keywordCount[token];
            }
        }
    }
}

const std::map<std::string, int>& LogAnalyzer::getLevelCount() const {
    return levelCount;
}

const std::map<std::string, int>& LogAnalyzer::getSourceCount() const {
    return sourceCount;
}

const std::map<std::string, int>& LogAnalyzer::getKeywordCount() const {
    return keywordCount;
}

const std::vector<AnomalySummary>& LogAnalyzer::getAnomalies() const {
    return anomalies;
}

static std::string normalizeKeyword(const std::string& keyword) {
    std::string copy = keyword;
    for (std::string::size_type i = 0; i < copy.size(); ++i) {
        char c = copy[i];
        if (c >= 'A' && c <= 'Z') {
            copy[i] = c - 'A' + 'a';
        }
    }
    return copy;
}

static bool anomalyExists(const std::vector<AnomalySummary>& summaries, LogEntry* entry) {
    for (std::vector<AnomalySummary>::const_iterator it = summaries.begin(); it != summaries.end(); ++it) {
        if (it->timestamp == entry->getTimestamp() && it->level == entry->getLevel() && it->source == entry->getSource() && it->description == entry->getMessage()) {
            return true;
        }
    }
    return false;
}

void LogAnalyzer::detectSpikes(int windowMinutes, std::string& alertMessage) {
    anomalies.clear();
    timeWindow.clear();
    std::map<std::string, std::vector<LogEntry*> > errorsBySource;
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        if (*it != NULL && normalizeKeyword((*it)->getLevel()) == "error") {
            errorsBySource[(*it)->getSource()].push_back(*it);
        }
    }
    if (errorsBySource.empty()) {
        alertMessage = "No error entries available for spike detection.";
    } else {
        std::vector<LogEntry*> errors;
        for (std::map<std::string, std::vector<LogEntry*> >::const_iterator it = errorsBySource.begin(); it != errorsBySource.end(); ++it) {
            const std::vector<LogEntry*>& sourceErrors = it->second;
            for (std::vector<LogEntry*>::const_iterator sourceIt = sourceErrors.begin(); sourceIt != sourceErrors.end(); ++sourceIt) {
                errors.push_back(*sourceIt);
            }
        }
        std::sort(errors.begin(), errors.end(), compareByTimestamp);
        std::time_t firstTime = errors.front()->getTimestamp();
        std::time_t lastTime = errors.back()->getTimestamp();
        double hours = static_cast<double>(lastTime - firstTime) / 3600.0;
        if (hours < 1.0) {
            hours = 1.0;
        }
        double average = static_cast<double>(errors.size()) / hours;
        if (average < 1.0) {
            average = 1.0;
        }
        double expectedInWindow = average * static_cast<double>(windowMinutes) / 60.0;
        int windowSeconds = windowMinutes * 60;
        int spikeThreshold = static_cast<int>(expectedInWindow * 3.0 + 0.5);
        if (spikeThreshold < 5) {
            spikeThreshold = 5;
        }
        bool spikeDetected = false;
        for (std::map<std::string, std::vector<LogEntry*> >::iterator it = errorsBySource.begin(); it != errorsBySource.end() && !spikeDetected; ++it) {
            std::vector<LogEntry*>& sourceErrors = it->second;
            std::sort(sourceErrors.begin(), sourceErrors.end(), compareByTimestamp);
            std::deque<LogEntry*> sourceWindow;
            for (std::vector<LogEntry*>::const_iterator sourceIt = sourceErrors.begin(); sourceIt != sourceErrors.end(); ++sourceIt) {
                LogEntry* entry = *sourceIt;
                sourceWindow.push_back(entry);
                while (!sourceWindow.empty() && sourceWindow.front()->getTimestamp() + windowSeconds < entry->getTimestamp()) {
                    sourceWindow.pop_front();
                }
                if (static_cast<int>(sourceWindow.size()) >= spikeThreshold) {
                    AnomalySummary summary;
                    std::ostringstream idStream;
                    idStream << "A" << (1000 + static_cast<int>(anomalies.size()));
                    summary.anomalyId = idStream.str();
                    summary.timestamp = entry->getTimestamp();
                    summary.level = "ERROR";
                    summary.source = it->first;
                    std::ostringstream descStream;
                    descStream << sourceWindow.size() << " ERRORs detected in last " << windowMinutes << " minutes from " << it->first;
                    summary.description = descStream.str();
                    summary.score = 0.0;
                    anomalies.push_back(summary);
                    std::ostringstream msgStream;
                    msgStream << "SPIKE ALERT - " << summary.description;
                    alertMessage = msgStream.str();
                    spikeDetected = true;
                    break;
                }
            }
        }
        if (!spikeDetected) {
            alertMessage = "No spike anomalies detected in the current data window.";
        }
    }

    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        if (entry->getAnomalyScore() >= 0.85 && !anomalyExists(anomalies, entry)) {
            AnomalySummary summary;
            std::ostringstream idStream;
            idStream << "A" << (1000 + static_cast<int>(anomalies.size()));
            summary.anomalyId = idStream.str();
            summary.timestamp = entry->getTimestamp();
            summary.level = entry->getLevel();
            summary.source = entry->getSource();
            summary.description = entry->getMessage();
            summary.score = entry->getAnomalyScore();
            anomalies.push_back(summary);
        }
    }
    if (!alertMessage.empty() && alertMessage == "No spike anomalies detected in the current data window." && !anomalies.empty()) {
        alertMessage.clear();
    }
    if (alertMessage.empty() && anomalies.empty()) {
        alertMessage = "No spikes or high-score anomalies found.";
    }
}

void LogAnalyzer::generateAnomalySummary(const std::string& alertFilename, std::string& errorMessage) {
    std::ofstream ofs(alertFilename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Could not open anomaly summary file.";
        return;
    }
    ofs << "anomalyID,timestamp,level,source,description,score\n";
    for (std::vector<AnomalySummary>::const_iterator it = anomalies.begin(); it != anomalies.end(); ++it) {
        ofs << it->anomalyId << "," << it->timestamp << "," << it->level << "," << it->source << ",";
        std::string escaped = it->description;
        for (std::string::size_type i = 0; i < escaped.size(); ++i) {
            if (escaped[i] == '"') {
                escaped.insert(i, "\"");
                ++i;
            }
        }
        if (escaped.find(',') != std::string::npos) {
            ofs << '"' << escaped << '"';
        } else {
            ofs << escaped;
        }
        ofs << "," << it->score << "\n";
    }
}

std::vector<LogEntry*> LogAnalyzer::searchByKeyword(const std::string& keyword) const {
    std::vector<LogEntry*> results;
    std::string normalized = normalizeKeyword(keyword);
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        std::string msg = normalizeKeyword(entry->getMessage());
        if (msg.find(normalized) != std::string::npos) {
            results.push_back(entry);
        }
    }
    return results;
}

std::vector<LogEntry*> LogAnalyzer::filterByLevel(const std::string& level) const {
    std::vector<LogEntry*> results;
    std::string normalized = normalizeKeyword(level);
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        std::string entryLevel = normalizeKeyword(entry->getLevel());
        if (entryLevel == normalized) {
            results.push_back(entry);
        }
    }
    return results;
}

std::vector<LogEntry*> LogAnalyzer::filterByTimeRange(std::time_t startTime, std::time_t endTime) const {
    std::vector<LogEntry*> results;
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        std::time_t ts = entry->getTimestamp();
        if (ts >= startTime && ts <= endTime) {
            results.push_back(entry);
        }
    }
    return results;
}

std::vector<LogEntry*> LogAnalyzer::combinedFilter(const std::string& level, const std::string& keyword, std::time_t startTime, std::time_t endTime) const {
    std::vector<LogEntry*> results;
    std::string normalizedLevel = normalizeKeyword(level);
    std::string normalizedKeyword = normalizeKeyword(keyword);
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        bool levelMatch = normalizedLevel.empty() || normalizeKeyword(entry->getLevel()) == normalizedLevel;
        bool keywordMatch = normalizedKeyword.empty() || normalizeKeyword(entry->getMessage()).find(normalizedKeyword) != std::string::npos;
        bool timeMatch = (startTime == 0 && endTime == 0) || (entry->getTimestamp() >= startTime && entry->getTimestamp() <= endTime);
        if (levelMatch && keywordMatch && timeMatch) {
            results.push_back(entry);
        }
    }
    return results;
}

struct AnomalyCompare {
    bool operator()(LogEntry* left, LogEntry* right) const {
        if (left == NULL || right == NULL) {
            return left == NULL && right != NULL;
        }
        return left->getAnomalyScore() < right->getAnomalyScore();
    }
};

std::vector<LogEntry*> LogAnalyzer::getTopAnomalies(int topN) const {
    std::vector<LogEntry*> sorted;
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        if (*it != NULL) {
            sorted.push_back(*it);
        }
    }
    std::stable_sort(sorted.begin(), sorted.end(), AnomalyCompare());
    if (static_cast<int>(sorted.size()) > topN) {
        sorted.resize(topN);
    }
    return sorted;
}

bool LogAnalyzer::saveFrequencyReport(const std::string& filename, std::string& errorMessage) const {
    std::ofstream ofs(filename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to write frequency report.";
        return false;
    }
    ofs << "category,key,count\n";
    for (std::map<std::string, int>::const_iterator it = levelCount.begin(); it != levelCount.end(); ++it) {
        ofs << "level," << it->first << "," << it->second << "\n";
    }
    for (std::map<std::string, int>::const_iterator it = sourceCount.begin(); it != sourceCount.end(); ++it) {
        ofs << "source," << it->first << "," << it->second << "\n";
    }
    int written = 0;
    for (std::map<std::string, int>::const_iterator it = keywordCount.begin(); it != keywordCount.end() && written < 20; ++it, ++written) {
        ofs << "keyword," << it->first << "," << it->second << "\n";
    }
    return true;
}

bool LogAnalyzer::saveAnomalySummaryCSV(const std::string& filename, std::string& errorMessage) const {
    std::ofstream ofs(filename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to write anomaly summary file.";
        return false;
    }
    ofs << "anomalyID,timestamp,level,source,description,score\n";
    for (std::vector<AnomalySummary>::const_iterator it = anomalies.begin(); it != anomalies.end(); ++it) {
        ofs << it->anomalyId << "," << it->timestamp << "," << it->level << "," << it->source << ",";
        std::string escaped = it->description;
        for (std::string::size_type i = 0; i < escaped.size(); ++i) {
            if (escaped[i] == '"') {
                escaped.insert(i, "\"");
                ++i;
            }
        }
        if (escaped.find(',') != std::string::npos) {
            ofs << '"' << escaped << '"';
        } else {
            ofs << escaped;
        }
        ofs << "," << it->score << "\n";
    }
    return true;
}

bool LogAnalyzer::saveHourlyDistributionCSV(const std::string& filename, std::string& errorMessage) const {
    std::map<int, int> hourCount;
    for (std::vector<LogEntry*>::const_iterator it = entries->begin(); it != entries->end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        std::time_t timestamp = entry->getTimestamp();
        std::tm* timeInfo = std::localtime(&timestamp);
        if (timeInfo != NULL) {
            ++hourCount[timeInfo->tm_hour];
        }
    }
    std::ofstream ofs(filename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to create hourly distribution file.";
        return false;
    }
    ofs << "hour,count\n";
    for (std::map<int, int>::const_iterator it = hourCount.begin(); it != hourCount.end(); ++it) {
        ofs << it->first << "," << it->second << "\n";
    }
    return true;
}
