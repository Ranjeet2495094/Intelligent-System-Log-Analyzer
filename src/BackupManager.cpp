#include "BackupManager.h"
#include <fstream>
#include <cstdio>
#include <cstring>

static void writeString(std::ofstream& ofs, const std::string& value) {
    int length = static_cast<int>(value.size());
    ofs.write(reinterpret_cast<const char*>(&length), sizeof(length));
    if (length > 0) {
        ofs.write(value.c_str(), length);
    }
}

static bool readString(std::ifstream& ifs, std::string& output) {
    int length = 0;
    ifs.read(reinterpret_cast<char*>(&length), sizeof(length));
    if (!ifs.good()) {
        return false;
    }
    if (length < 0) {
        return false;
    }
    output.clear();
    if (length > 0) {
        char* buffer = new char[length];
        ifs.read(buffer, length);
        if (!ifs.good()) {
            delete [] buffer;
            return false;
        }
        output.assign(buffer, length);
        delete [] buffer;
    }
    return true;
}

BackupManager::BackupManager() {}
BackupManager::~BackupManager() {}

bool BackupManager::createBackup(const std::string& filename, const std::vector<LogEntry*>& entries, std::string& errorMessage) const {
    std::string tempFile = filename + ".tmp";
    std::ofstream ofs(tempFile.c_str(), std::ios::binary);
    if (!ofs.is_open()) {
        errorMessage = "Cannot open backup file.";
        return false;
    }
    int count = static_cast<int>(entries.size());
    ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (std::vector<LogEntry*>::const_iterator it = entries.begin(); it != entries.end(); ++it) {
        LogEntry* entry = *it;
        std::string type = entry->getType();
        writeString(ofs, type);
        std::time_t timestamp = entry->getTimestamp();
        ofs.write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
        writeString(ofs, entry->getLevel());
        writeString(ofs, entry->getSource());
        writeString(ofs, entry->getMessage());
        double score = entry->getAnomalyScore();
        ofs.write(reinterpret_cast<const char*>(&score), sizeof(score));
    }
    ofs.close();
    if (std::rename(tempFile.c_str(), filename.c_str()) != 0) {
        std::remove(tempFile.c_str());
        errorMessage = "Atomic backup rename failed.";
        return false;
    }
    return true;
}

bool BackupManager::restoreBackup(const std::string& filename, std::vector<LogEntry*>& entries, std::string& errorMessage) const {
    std::ifstream ifs(filename.c_str(), std::ios::binary);
    if (!ifs.is_open()) {
        errorMessage = "Cannot open backup file for restore.";
        return false;
    }
    int count = 0;
    ifs.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!ifs.good() || count < 0) {
        errorMessage = "Backup file is corrupted.";
        return false;
    }
    for (int i = 0; i < count; ++i) {
        std::string type;
        if (!readString(ifs, type)) {
            errorMessage = "Backup file read failure.";
            return false;
        }
        std::time_t ts;
        ifs.read(reinterpret_cast<char*>(&ts), sizeof(ts));
        std::string level;
        std::string source;
        std::string message;
        if (!readString(ifs, level) || !readString(ifs, source) || !readString(ifs, message)) {
            errorMessage = "Backup file read failure.";
            return false;
        }
        double score = 0.0;
        ifs.read(reinterpret_cast<char*>(&score), sizeof(score));
        if (!ifs.good()) {
            errorMessage = "Backup file read failure.";
            return false;
        }
        LogEntry* entry = NULL;
        if (type == "INFO") {
            entry = new InfoLogEntry(ts, source, message);
        } else if (type == "WARNING") {
            entry = new WarningLogEntry(ts, source, message);
        } else if (type == "ERROR") {
            entry = new ErrorLogEntry(ts, source, message);
        } else if (type == "SECURITY") {
            entry = new SecurityLogEntry(ts, source, message);
        } else {
            entry = new InfoLogEntry(ts, source, message);
        }
        entry->setAnomalyScore(score);
        entry->setLevel(level);
        entries.push_back(entry);
    }
    return true;
}
