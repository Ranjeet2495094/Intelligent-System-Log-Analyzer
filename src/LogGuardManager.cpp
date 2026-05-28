#include "LogGuardManager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <dirent.h>
#include <sys/stat.h>
#include <cstring>

LogGuardManager::LogGuardManager()
    : analyzer(&entries), parsedFilename("parsed_entries.csv"), anomalyFilename("anomaly_summary.csv"), alertFilename("alerts.log"), frequencyFilename("frequency_report.csv"), backupFilename("backup.dat") {
    initializeFiles();
}

LogGuardManager::~LogGuardManager() {
    clearEntries();
}

void LogGuardManager::clearEntries() {
    for (std::vector<LogEntry*>::iterator it = entries.begin(); it != entries.end(); ++it) {
        delete *it;
    }
    entries.clear();
}

std::string LogGuardManager::buildEntryId(int index) {
    std::ostringstream oss;
    oss << "E" << (1000 + index);
    return oss.str();
}

std::string LogGuardManager::buildAnomalyId(int index) {
    std::ostringstream oss;
    oss << "A" << (1000 + index);
    return oss.str();
}

std::string LogGuardManager::makeUpper(const std::string& input) {
    std::string copy = input;
    for (std::string::size_type i = 0; i < copy.size(); ++i) {
        char c = copy[i];
        if (c >= 'a' && c <= 'z') {
            copy[i] = c - 'a' + 'A';
        }
    }
    return copy;
}

bool LogGuardManager::initializeFiles() {
    std::ofstream ofs;
    ofs.open(parsedFilename.c_str(), std::ios::app);
    if (!ofs.is_open()) {
        return false;
    }
    ofs.close();
    ofs.open(anomalyFilename.c_str(), std::ios::app);
    if (!ofs.is_open()) {
        return false;
    }
    ofs.close();
    ofs.open(alertFilename.c_str(), std::ios::app);
    if (!ofs.is_open()) {
        return false;
    }
    ofs.close();
    ofs.open(frequencyFilename.c_str(), std::ios::app);
    if (!ofs.is_open()) {
        return false;
    }
    ofs.close();
    return true;
}

bool LogGuardManager::parseSingleFile(const std::string& filename, std::string& errorMessage) {
    std::vector<LogEntry*> newlyParsed;
    if (!parser.parseFile(filename, newlyParsed, errorMessage)) {
        return false;
    }
    for (std::vector<LogEntry*>::iterator it = newlyParsed.begin(); it != newlyParsed.end(); ++it) {
        entries.push_back(*it);
    }
    if (!parser.saveParsedEntries(parsedFilename, entries, errorMessage)) {
        return false;
    }
    analyzer.analyzeFrequencies();
    std::string unused;
    analyzer.saveFrequencyReport(frequencyFilename, unused);
    return true;
}

bool LogGuardManager::parseFolder(const std::string& folderPath, std::string& errorMessage) {
    DIR* dir = opendir(folderPath.c_str());
    if (dir == NULL) {
        errorMessage = "Cannot open folder: " + folderPath;
        return false;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") {
            continue;
        }
        std::string fullPath = folderPath + "/" + name;
        struct stat st;
        if (stat(fullPath.c_str(), &st) != 0) {
            continue;
        }
        if ((st.st_mode & S_IFMT) == S_IFREG) {
            if (name.size() > 4 && name.substr(name.size() - 4) == ".log") {
                if (!parseSingleFile(fullPath, errorMessage)) {
                    closedir(dir);
                    return false;
                }
            }
        }
    }
    closedir(dir);
    return true;
}

bool LogGuardManager::loadPreviouslyParsedData(std::string& errorMessage) {
    clearEntries();
    if (!parser.loadParsedEntries(parsedFilename, entries, errorMessage)) {
        return false;
    }
    analyzer.analyzeFrequencies();
    return true;
}

void LogGuardManager::viewParsingSummary() const {
    std::cout << "Parsed entries: " << entries.size() << std::endl;
    std::cout << "Stored files: " << parsedFilename << ", " << anomalyFilename << ", " << alertFilename << ", " << frequencyFilename << std::endl;
}

std::vector<LogEntry*> LogGuardManager::searchByKeyword(const std::string& keyword) const {
    return analyzer.searchByKeyword(keyword);
}

std::vector<LogEntry*> LogGuardManager::filterByLevel(const std::string& level) const {
    return analyzer.filterByLevel(level);
}

std::vector<LogEntry*> LogGuardManager::filterByTimeRange(std::time_t startTime, std::time_t endTime) const {
    return analyzer.filterByTimeRange(startTime, endTime);
}

std::vector<LogEntry*> LogGuardManager::combinedFilter(const std::string& level, const std::string& keyword, std::time_t startTime, std::time_t endTime) const {
    return analyzer.combinedFilter(level, keyword, startTime, endTime);
}

bool LogGuardManager::runFullAnomalyDetection(std::string& message) {
    analyzer.analyzeFrequencies();
    analyzer.detectSpikes(15, message);
    std::string errorMessage;
    if (!analyzer.saveAnomalySummaryCSV(anomalyFilename, errorMessage)) {
        message = "Failed to save anomaly summary: " + errorMessage;
        return false;
    }
    return true;
}

bool LogGuardManager::detectErrorSpikes(std::string& message) {
    return runFullAnomalyDetection(message);
}

std::vector<LogEntry*> LogGuardManager::viewTopAnomalies(int topN) const {
    return analyzer.getTopAnomalies(topN);
}

bool LogGuardManager::generateCriticalAlerts(std::string& errorMessage) {
    std::string alertMessage;
    if (!runFullAnomalyDetection(alertMessage)) {
        errorMessage = alertMessage;
        return false;
    }
    std::ofstream ofs(alertFilename.c_str(), std::ios::app);
    if (!ofs.is_open()) {
        errorMessage = "Unable to append to alerts log.";
        return false;
    }
    std::vector<LogEntry*> top = analyzer.getTopAnomalies(10);
    for (std::vector<LogEntry*>::const_iterator it = top.begin(); it != top.end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        if (entry->getAnomalyScore() >= 0.9 || makeUpper(entry->getLevel()) == "ERROR") {
            std::ostringstream timestampStream;
            timestampStream << std::time(NULL);
            ofs << "[" << timestampStream.str() << "] CRITICAL ALERT - " << entry->getMessage() << " (Score: " << entry->getAnomalyScore() << ")\n";
        }
    }
    errorMessage = alertMessage;
    return true;
}

bool LogGuardManager::generateFrequencyReport(std::string& errorMessage) {
    analyzer.analyzeFrequencies();
    if (!analyzer.saveFrequencyReport(frequencyFilename, errorMessage)) {
        return false;
    }
    return true;
}

bool LogGuardManager::generateHourlyDistributionReport(std::string& errorMessage) {
    analyzer.analyzeFrequencies();
    if (!analyzer.saveHourlyDistributionCSV("reports/hourly_distribution.csv", errorMessage)) {
        return false;
    }
    return true;
}

bool LogGuardManager::exportReports(std::string& errorMessage) {
    analyzer.analyzeFrequencies();
    if (!reporter.exportEntriesToCSV("reports/parsed_entries_export.csv", entries, errorMessage)) {
        return false;
    }
    if (!reporter.exportFrequencyReport("reports/frequency_export.csv", analyzer.getLevelCount(), analyzer.getSourceCount(), analyzer.getKeywordCount(), errorMessage)) {
        return false;
    }
    if (!reporter.exportAnomalySummary("reports/anomaly_export.csv", analyzer.getAnomalies(), errorMessage)) {
        return false;
    }
    return true;
}

bool LogGuardManager::createBackup(std::string& errorMessage) {
    if (!backupManager.createBackup(backupFilename, entries, errorMessage)) {
        return false;
    }
    return true;
}

bool LogGuardManager::restoreBackup(std::string& errorMessage) {
    clearEntries();
    if (!backupManager.restoreBackup(backupFilename, entries, errorMessage)) {
        return false;
    }
    if (!parser.saveParsedEntries(parsedFilename, entries, errorMessage)) {
        return false;
    }
    analyzer.analyzeFrequencies();
    return true;
}

bool LogGuardManager::clearParsedData(std::string& errorMessage) {
    clearEntries();
    std::ofstream ofs;
    ofs.open(parsedFilename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to clear parsed data file.";
        return false;
    }
    ofs.close();
    ofs.open(anomalyFilename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to clear anomaly file.";
        return false;
    }
    ofs.close();
    ofs.open(frequencyFilename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to clear frequency file.";
        return false;
    }
    ofs.close();
    return true;
}
