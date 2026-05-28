#include "ReportGenerator.h"
#include <fstream>
#include <sstream>

ReportGenerator::ReportGenerator() {}
ReportGenerator::~ReportGenerator() {}

bool ReportGenerator::exportEntriesToCSV(const std::string& filename, const std::vector<LogEntry*>& entries, std::string& errorMessage) const {
    std::ofstream ofs(filename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to open report file: " + filename;
        return false;
    }
    ofs << "timestamp,level,source,message,anomalyScore\n";
    for (std::vector<LogEntry*>::const_iterator it = entries.begin(); it != entries.end(); ++it) {
        LogEntry* entry = *it;
        if (entry == NULL) {
            continue;
        }
        ofs << entry->getTimestamp() << "," << entry->getLevel() << "," << entry->getSource() << ",";
        std::string text = entry->getMessage();
        for (std::string::size_type i = 0; i < text.size(); ++i) {
            if (text[i] == '"') {
                text.insert(i, "\"");
                ++i;
            }
        }
        if (text.find(',') != std::string::npos) {
            ofs << '"' << text << '"';
        } else {
            ofs << text;
        }
        ofs << "," << entry->getAnomalyScore() << "\n";
    }
    return true;
}

bool ReportGenerator::exportAnomalySummary(const std::string& filename, const std::vector<AnomalySummary>& anomalies, std::string& errorMessage) const {
    std::ofstream ofs(filename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to open anomaly report file: " + filename;
        return false;
    }
    ofs << "anomalyID,timestamp,level,source,description,score\n";
    for (std::vector<AnomalySummary>::const_iterator it = anomalies.begin(); it != anomalies.end(); ++it) {
        ofs << it->anomalyId << "," << it->timestamp << "," << it->level << "," << it->source << ",";
        std::string text = it->description;
        for (std::string::size_type i = 0; i < text.size(); ++i) {
            if (text[i] == '"') {
                text.insert(i, "\"");
                ++i;
            }
        }
        if (text.find(',') != std::string::npos) {
            ofs << '"' << text << '"';
        } else {
            ofs << text;
        }
        ofs << "," << it->score << "\n";
    }
    return true;
}

bool ReportGenerator::exportFrequencyReport(const std::string& filename, const std::map<std::string, int>& levelCount, const std::map<std::string, int>& sourceCount, const std::map<std::string, int>& keywordCount, std::string& errorMessage) const {
    std::ofstream ofs(filename.c_str());
    if (!ofs.is_open()) {
        errorMessage = "Unable to open frequency export: " + filename;
        return false;
    }
    ofs << "category,key,count\n";
    for (std::map<std::string, int>::const_iterator it = levelCount.begin(); it != levelCount.end(); ++it) {
        ofs << "level," << it->first << "," << it->second << "\n";
    }
    for (std::map<std::string, int>::const_iterator it = sourceCount.begin(); it != sourceCount.end(); ++it) {
        ofs << "source," << it->first << "," << it->second << "\n";
    }
    int count = 0;
    for (std::map<std::string, int>::const_iterator it = keywordCount.begin(); it != keywordCount.end() && count < 20; ++it, ++count) {
        ofs << "keyword," << it->first << "," << it->second << "\n";
    }
    return true;
}
