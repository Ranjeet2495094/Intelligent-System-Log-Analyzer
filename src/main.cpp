#include "LogGuardManager.h"
#include "LogParser.h"
#include <iostream>
#include <sstream>
#include <string>
#include <ctime>

static void printMainMenu() {
    std::cout << "============================================================" << std::endl;
    std::cout << "LOGGUARD - Intelligent Log Analyzer & Anomaly Detector" << std::endl;
    std::cout << "TechNova Infosystems Pvt. Ltd." << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << "1. Log Ingestion & Parsing" << std::endl;
    std::cout << "2. Search & Filter Logs" << std::endl;
    std::cout << "3. Anomaly Detection & Alerts" << std::endl;
    std::cout << "4. Analytics & Reports" << std::endl;
    std::cout << "5. System Backup & Restore" << std::endl;
    std::cout << "6. Exit" << std::endl;
    std::cout << "Enter your choice (1-6): ";
}

static void printIngestionMenu() {
    std::cout << "------------------- Log Ingestion -------------------" << std::endl;
    std::cout << "1. Parse Single Log File" << std::endl;
    std::cout << "2. Parse Multiple Log Files (from folder)" << std::endl;
    std::cout << "3. Load Previously Parsed Data" << std::endl;
    std::cout << "4. View Parsing Summary" << std::endl;
    std::cout << "5. Back to Main Menu" << std::endl;
    std::cout << "Enter your choice (1-5): ";
}

static void printSearchMenu() {
    std::cout << "------------------- Search & Filter -------------------" << std::endl;
    std::cout << "1. Search by Keyword" << std::endl;
    std::cout << "2. Filter by Log Level (INFO/WARNING/ERROR/SECURITY)" << std::endl;
    std::cout << "3. Filter by Time Range" << std::endl;
    std::cout << "4. Combined Filter (Level + Keyword + Time)" << std::endl;
    std::cout << "5. Back to Main Menu" << std::endl;
    std::cout << "Enter your choice (1-5): ";
}

static void printAnomalyMenu() {
    std::cout << "------------------- Anomaly Detection -------------------" << std::endl;
    std::cout << "1. Run Full Anomaly Detection" << std::endl;
    std::cout << "2. Detect Error Spikes (Time Window Analysis)" << std::endl;
    std::cout << "3. View All Anomalies (Sorted by Score)" << std::endl;
    std::cout << "4. Generate Critical Alerts" << std::endl;
    std::cout << "5. Back to Main Menu" << std::endl;
    std::cout << "Enter your choice (1-5): ";
}

static void printAnalyticsMenu() {
    std::cout << "------------------- Analytics & Reports -------------------" << std::endl;
    std::cout << "1. Frequency Analysis (Error Types & Keywords)" << std::endl;
    std::cout << "2. Top 10 Most Frequent Errors" << std::endl;
    std::cout << "3. Hourly Distribution Report" << std::endl;
    std::cout << "4. Source-wise Summary" << std::endl;
    std::cout << "5. Export Report to CSV" << std::endl;
    std::cout << "6. Back to Main Menu" << std::endl;
    std::cout << "Enter your choice (1-6): ";
}

static void printBackupMenu() {
    std::cout << "------------------- System Maintenance -------------------" << std::endl;
    std::cout << "1. Create Full Backup" << std::endl;
    std::cout << "2. Restore from Backup" << std::endl;
    std::cout << "3. Clear Parsed Data" << std::endl;
    std::cout << "4. Back to Main Menu" << std::endl;
    std::cout << "Enter your choice (1-4): ";
}

static bool readInteger(int& output) {
    std::string input;
    if (!std::getline(std::cin, input)) {
        return false;
    }
    std::istringstream iss(input);
    iss >> output;
    return !iss.fail();
}

static bool parseDateTime(const std::string& text, std::time_t& output) {
    return LogParser::parseTimestamp(text, output);
}

static void displayEntries(const std::vector<LogEntry*>& entries) {
    for (std::vector<LogEntry*>::const_iterator it = entries.begin(); it != entries.end(); ++it) {
        if (*it != NULL) {
            (*it)->display();
        }
    }
}

int main() {
    LogGuardManager manager;
    int choice = 0;
    while (true) {
        printMainMenu();
        if (!readInteger(choice)) {
            std::cout << "Invalid input." << std::endl;
            continue;
        }
        if (choice == 1) {
            int option = 0;
            while (option != 5) {
                printIngestionMenu();
                if (!readInteger(option)) {
                    std::cout << "Invalid input." << std::endl;
                    continue;
                }
                if (option == 1) {
                    std::cout << "Enter log file path: ";
                    std::string path;
                    std::getline(std::cin, path);
                    std::string error;
                    if (manager.parseSingleFile(path, error)) {
                        std::cout << "Parsed file successfully." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 2) {
                    std::cout << "Enter folder path containing .log files: ";
                    std::string folder;
                    std::getline(std::cin, folder);
                    std::string error;
                    if (manager.parseFolder(folder, error)) {
                        std::cout << "Parsed folder successfully." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 3) {
                    std::string error;
                    if (manager.loadPreviouslyParsedData(error)) {
                        std::cout << "Previously parsed data loaded." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 4) {
                    manager.viewParsingSummary();
                }
            }
        } else if (choice == 2) {
            int option = 0;
            while (option != 5) {
                printSearchMenu();
                if (!readInteger(option)) {
                    std::cout << "Invalid input." << std::endl;
                    continue;
                }
                if (option == 1) {
                    std::cout << "Enter keyword: ";
                    std::string keyword;
                    std::getline(std::cin, keyword);
                    displayEntries(manager.searchByKeyword(keyword));
                } else if (option == 2) {
                    std::cout << "Enter level (INFO/WARNING/ERROR/SECURITY): ";
                    std::string level;
                    std::getline(std::cin, level);
                    displayEntries(manager.filterByLevel(level));
                } else if (option == 3) {
                    std::cout << "Enter start date/time (YYYY-MM-DD HH:MM:SS): ";
                    std::string startText;
                    std::getline(std::cin, startText);
                    std::cout << "Enter end date/time (YYYY-MM-DD HH:MM:SS): ";
                    std::string endText;
                    std::getline(std::cin, endText);
                    std::time_t startTime;
                    std::time_t endTime;
                    if (!parseDateTime(startText, startTime) || !parseDateTime(endText, endTime)) {
                        std::cout << "Invalid date/time format." << std::endl;
                        continue;
                    }
                    displayEntries(manager.filterByTimeRange(startTime, endTime));
                } else if (option == 4) {
                    std::cout << "Enter level (or leave blank): ";
                    std::string level;
                    std::getline(std::cin, level);
                    std::cout << "Enter keyword (or leave blank): ";
                    std::string keyword;
                    std::getline(std::cin, keyword);
                    std::cout << "Enter start date/time (YYYY-MM-DD HH:MM:SS or leave blank): ";
                    std::string startText;
                    std::getline(std::cin, startText);
                    std::cout << "Enter end date/time (YYYY-MM-DD HH:MM:SS or leave blank): ";
                    std::string endText;
                    std::getline(std::cin, endText);
                    std::time_t startTime = 0;
                    std::time_t endTime = 0;
                    if (!startText.empty() && !parseDateTime(startText, startTime)) {
                        std::cout << "Invalid start date/time format." << std::endl;
                        continue;
                    }
                    if (!endText.empty() && !parseDateTime(endText, endTime)) {
                        std::cout << "Invalid end date/time format." << std::endl;
                        continue;
                    }
                    displayEntries(manager.combinedFilter(level, keyword, startTime, endTime));
                }
            }
        } else if (choice == 3) {
            int option = 0;
            while (option != 5) {
                printAnomalyMenu();
                if (!readInteger(option)) {
                    std::cout << "Invalid input." << std::endl;
                    continue;
                }
                if (option == 1) {
                    std::string message;
                    if (manager.runFullAnomalyDetection(message)) {
                        std::cout << "Anomaly detection completed." << std::endl;
                        std::cout << message << std::endl;
                    } else {
                        std::cout << "Error: " << message << std::endl;
                    }
                } else if (option == 2) {
                    std::string message;
                    if (manager.detectErrorSpikes(message)) {
                        std::cout << message << std::endl;
                    } else {
                        std::cout << "Error: " << message << std::endl;
                    }
                } else if (option == 3) {
                    std::vector<LogEntry*> anomalies = manager.viewTopAnomalies(10);
                    displayEntries(anomalies);
                } else if (option == 4) {
                    std::string error;
                    if (manager.generateCriticalAlerts(error)) {
                        std::cout << "Critical alerts generated." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                }
            }
        } else if (choice == 4) {
            int option = 0;
            while (option != 6) {
                printAnalyticsMenu();
                if (!readInteger(option)) {
                    std::cout << "Invalid input." << std::endl;
                    continue;
                }
                if (option == 1) {
                    std::string error;
                    if (manager.generateFrequencyReport(error)) {
                        std::cout << "Frequency analysis saved to " << "frequency_report.csv" << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 2) {
                    std::vector<LogEntry*> top = manager.viewTopAnomalies(10);
                    displayEntries(top);
                } else if (option == 3) {
                    std::string error;
                    if (manager.generateHourlyDistributionReport(error)) {
                        std::cout << "Hourly distribution report saved to reports/hourly_distribution.csv" << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 4) {
                    std::string error;
                    if (manager.generateFrequencyReport(error)) {
                        std::cout << "Source-wise summary saved as part of frequency report." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 5) {
                    std::string error;
                    if (manager.exportReports(error)) {
                        std::cout << "Reports exported to reports/ folder." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                }
            }
        } else if (choice == 5) {
            int option = 0;
            while (option != 4) {
                printBackupMenu();
                if (!readInteger(option)) {
                    std::cout << "Invalid input." << std::endl;
                    continue;
                }
                if (option == 1) {
                    std::string error;
                    if (manager.createBackup(error)) {
                        std::cout << "Backup created." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 2) {
                    std::string error;
                    if (manager.restoreBackup(error)) {
                        std::cout << "Backup restored." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                } else if (option == 3) {
                    std::string error;
                    if (manager.clearParsedData(error)) {
                        std::cout << "Parsed data cleared." << std::endl;
                    } else {
                        std::cout << "Error: " << error << std::endl;
                    }
                }
            }
        } else if (choice == 6) {
            std::cout << "Exiting LogGuard." << std::endl;
            break;
        } else {
            std::cout << "Please choose a valid menu option." << std::endl;
        }
    }
    return 0;
}
