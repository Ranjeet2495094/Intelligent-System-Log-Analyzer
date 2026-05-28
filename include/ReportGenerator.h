#ifndef REPORTGENERATOR_H
#define REPORTGENERATOR_H

#include <string>
#include <vector>
#include "LogEntry.h"
#include "LogAnalyzer.h"

class ReportGenerator {
public:
    ReportGenerator();
    virtual ~ReportGenerator();

    bool exportEntriesToCSV(const std::string& filename, const std::vector<LogEntry*>& entries, std::string& errorMessage) const;
    bool exportAnomalySummary(const std::string& filename, const std::vector<AnomalySummary>& anomalies, std::string& errorMessage) const;
    bool exportFrequencyReport(const std::string& filename, const std::map<std::string, int>& levelCount, const std::map<std::string, int>& sourceCount, const std::map<std::string, int>& keywordCount, std::string& errorMessage) const;
};

#endif // REPORTGENERATOR_H
