#ifndef LOGANALYZER_H
#define LOGANALYZER_H

#include <vector>
#include <map>
#include <deque>
#include <string>
#include <utility>
#include "LogEntry.h"

struct AnomalySummary {
    std::string anomalyId;
    std::time_t timestamp;
    std::string level;
    std::string source;
    std::string description;
    double score;
};

class LogAnalyzer {
private:
    std::vector<LogEntry*>* entries;
    std::map<std::string, int> levelCount;
    std::map<std::string, int> sourceCount;
    std::map<std::string, int> keywordCount;
    std::deque<LogEntry*> timeWindow;
    std::vector<AnomalySummary> anomalies;

public:
    LogAnalyzer(std::vector<LogEntry*>* allEntries);
    ~LogAnalyzer();

    void analyzeFrequencies();
    const std::map<std::string, int>& getLevelCount() const;
    const std::map<std::string, int>& getSourceCount() const;
    const std::map<std::string, int>& getKeywordCount() const;
    const std::vector<AnomalySummary>& getAnomalies() const;

    void detectSpikes(int windowMinutes, std::string& alertMessage);
    void generateAnomalySummary(const std::string& alertFilename, std::string& errorMessage);
    std::vector<LogEntry*> searchByKeyword(const std::string& keyword) const;
    std::vector<LogEntry*> filterByLevel(const std::string& level) const;
    std::vector<LogEntry*> filterByTimeRange(std::time_t startTime, std::time_t endTime) const;
    std::vector<LogEntry*> combinedFilter(const std::string& level, const std::string& keyword, std::time_t startTime, std::time_t endTime) const;
    std::vector<LogEntry*> getTopAnomalies(int topN) const;
    bool saveFrequencyReport(const std::string& filename, std::string& errorMessage) const;
    bool saveAnomalySummaryCSV(const std::string& filename, std::string& errorMessage) const;
    bool saveHourlyDistributionCSV(const std::string& filename, std::string& errorMessage) const;
};

#endif // LOGANALYZER_H
