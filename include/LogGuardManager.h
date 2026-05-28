#ifndef LOGGUARDMANAGER_H
#define LOGGUARDMANAGER_H

#include <string>
#include <vector>
#include "LogEntry.h"
#include "LogParser.h"
#include "LogAnalyzer.h"
#include "ReportGenerator.h"
#include "BackupManager.h"

class LogGuardManager {
private:
    std::vector<LogEntry*> entries;
    LogParser parser;
    LogAnalyzer analyzer;
    ReportGenerator reporter;
    BackupManager backupManager;
    std::string parsedFilename;
    std::string anomalyFilename;
    std::string alertFilename;
    std::string frequencyFilename;
    std::string backupFilename;

    void clearEntries();
    static std::string buildEntryId(int index);
    static std::string buildAnomalyId(int index);
    static std::string makeUpper(const std::string& input);

public:
    LogGuardManager();
    ~LogGuardManager();

    bool initializeFiles();
    bool parseSingleFile(const std::string& filename, std::string& errorMessage);
    bool parseFolder(const std::string& folderPath, std::string& errorMessage);
    bool loadPreviouslyParsedData(std::string& errorMessage);
    void viewParsingSummary() const;
    std::vector<LogEntry*> searchByKeyword(const std::string& keyword) const;
    std::vector<LogEntry*> filterByLevel(const std::string& level) const;
    std::vector<LogEntry*> filterByTimeRange(std::time_t startTime, std::time_t endTime) const;
    std::vector<LogEntry*> combinedFilter(const std::string& level, const std::string& keyword, std::time_t startTime, std::time_t endTime) const;
    bool runFullAnomalyDetection(std::string& message);
    bool detectErrorSpikes(std::string& message);
    std::vector<LogEntry*> viewTopAnomalies(int topN) const;
    bool generateCriticalAlerts(std::string& errorMessage);
    bool generateFrequencyReport(std::string& errorMessage);
    bool generateHourlyDistributionReport(std::string& errorMessage);
    bool exportReports(std::string& errorMessage);
    bool createBackup(std::string& errorMessage);
    bool restoreBackup(std::string& errorMessage);
    bool clearParsedData(std::string& errorMessage);
};

#endif // LOGGUARDMANAGER_H
