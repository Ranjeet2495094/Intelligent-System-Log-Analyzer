#ifndef BACKUPMANAGER_H
#define BACKUPMANAGER_H

#include <string>
#include <vector>
#include "LogEntry.h"

class BackupManager {
public:
    BackupManager();
    virtual ~BackupManager();

    bool createBackup(const std::string& filename, const std::vector<LogEntry*>& entries, std::string& errorMessage) const;
    bool restoreBackup(const std::string& filename, std::vector<LogEntry*>& entries, std::string& errorMessage) const;
};

#endif // BACKUPMANAGER_H
