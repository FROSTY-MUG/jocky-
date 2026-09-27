#include "detect/byovd.hpp"
#include "collectors/driver.hpp"
#include "errors.hpp"
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include <cctype>

namespace jocky {

std::vector<Finding> ByovdDetector::check_driver_hashes(const nlohmann::json& drivers, const std::string& blocklist_path) {
    std::vector<Finding> findings;

    std::string path = blocklist_path;
    if (path.empty()) {
        path = "agent/windows-cpp/data/loldrivers_subset.json";
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        file.open("../../data/loldrivers_subset.json");
    }
    if (!file.is_open()) {
        file.open("../../../agent/windows-cpp/data/loldrivers_subset.json");
    }
    if (!file.is_open()) {
        throw DetectionError("Failed to open LOLdrivers blocklist");
    }

    nlohmann::json blocklist;
    try {
        file >> blocklist;
    } catch (const std::exception& e) {
        throw DetectionError(std::string("Failed to parse blocklist: ") + e.what());
    }

    std::unordered_set<std::string> bad_hashes;
    if (blocklist.contains("entries") && blocklist["entries"].is_array()) {
        for (const auto& entry : blocklist["entries"]) {
            if (entry.contains("sha256") && entry["sha256"].is_string()) {
                std::string hash = entry["sha256"].get<std::string>();
                std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (!hash.empty()) {
                    bad_hashes.insert(hash);
                }
            }
        }
    }

    for (const auto& driver : drivers) {
        std::string sha256 = driver.value("sha256", "");
        std::transform(sha256.begin(), sha256.end(), sha256.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!sha256.empty() && bad_hashes.find(sha256) != bad_hashes.end()) {
            Finding f;
            f.severity = Severity::High;
            f.title = "Known Vulnerable Driver Loaded (BYOVD)";
            f.evidence = driver.value("path", "");
            f.mitre = "T1068";
            findings.push_back(f);
        }
    }

    return findings;
}

std::vector<Finding> ByovdDetector::detect() {
    return check_driver_hashes(DriverCollector::collect());
}

} // namespace jocky
