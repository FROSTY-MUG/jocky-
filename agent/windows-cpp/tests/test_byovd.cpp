#include "detect/byovd.hpp"
#include <iostream>

using namespace jocky;

int main() {
    std::cout << "[RUNNING] test_byovd..." << std::endl;

    // 1. Feed a known-bad hash from LOLdrivers blocklist -> emits a Finding
    std::string known_bad_hash = "314a51fcf6e37eb8550a826df085d5c88c43eb1438682f3a6c33632d36956136";
    nlohmann::json bad_driver_input = nlohmann::json::array({
        {
            {"name", "iobios64.sys"},
            {"path", "C:\\Windows\\System32\\drivers\\iobios64.sys"},
            {"sha256", known_bad_hash}
        }
    });

    std::vector<Finding> bad_findings = ByovdDetector::check_driver_hashes(bad_driver_input);
    if (bad_findings.size() != 1) {
        std::cerr << "Expected 1 finding for known-bad hash, got " << bad_findings.size() << std::endl;
        return 1;
    }
    if (bad_findings[0].severity != Severity::High || bad_findings[0].mitre != "T1068") {
        std::cerr << "Finding does not have expected Severity::High or MITRE T1068" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Known-bad hash detected with Severity::High, MITRE T1068." << std::endl;

    // 2. Feed a known-good hash -> emits nothing
    std::string known_good_hash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    nlohmann::json good_driver_input = nlohmann::json::array({
        {
            {"name", "clean_driver.sys"},
            {"path", "C:\\Windows\\System32\\drivers\\clean_driver.sys"},
            {"sha256", known_good_hash}
        }
    });

    std::vector<Finding> good_findings = ByovdDetector::check_driver_hashes(good_driver_input);
    if (!good_findings.empty()) {
        std::cerr << "Expected 0 findings for known-good hash, got " << good_findings.size() << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Known-good hash produced 0 findings." << std::endl;

    std::cout << "[SUCCESS] All BYOVD tests passed." << std::endl;
    return 0;
}
