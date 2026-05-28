#ifndef LOGENTRY_H
#define LOGENTRY_H

#include <string>
#include <fstream>
#include <ctime>

class LogEntry {
protected:
    std::time_t timestamp;
    std::string level;
    std::string message;
    std::string source;
    double anomalyScore;

public:
    LogEntry();
    LogEntry(std::time_t ts, const std::string& lvl, const std::string& src, const std::string& msg);
    virtual ~LogEntry();

    std::time_t getTimestamp() const;
    const std::string& getLevel() const;
    const std::string& getMessage() const;
    const std::string& getSource() const;
    double getAnomalyScore() const;
    void setLevel(const std::string& lvl);
    void setAnomalyScore(double score);

    virtual std::string getType() const = 0;
    virtual double calculateAnomalyScore() = 0;
    virtual void display() const;
    virtual void saveToCSV(std::ofstream& ofs, const std::string& entryId) const;
};

class InfoLogEntry : public LogEntry {
public:
    InfoLogEntry(std::time_t ts, const std::string& src, const std::string& msg);
    virtual ~InfoLogEntry();
    virtual std::string getType() const;
    virtual double calculateAnomalyScore();
    virtual void display() const;
};

class WarningLogEntry : public LogEntry {
public:
    WarningLogEntry(std::time_t ts, const std::string& src, const std::string& msg);
    virtual ~WarningLogEntry();
    virtual std::string getType() const;
    virtual double calculateAnomalyScore();
    virtual void display() const;
};

class ErrorLogEntry : public LogEntry {
public:
    ErrorLogEntry(std::time_t ts, const std::string& src, const std::string& msg);
    virtual ~ErrorLogEntry();
    virtual std::string getType() const;
    virtual double calculateAnomalyScore();
    virtual void display() const;
};

class SecurityLogEntry : public LogEntry {
public:
    SecurityLogEntry(std::time_t ts, const std::string& src, const std::string& msg);
    virtual ~SecurityLogEntry();
    virtual std::string getType() const;
    virtual double calculateAnomalyScore();
    virtual void display() const;
};

#endif // LOGENTRY_H
