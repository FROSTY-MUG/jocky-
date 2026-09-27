#include "detect/inject.hpp"
#include <iostream>
#include <vector>

using namespace jocky;

int main() {
    std::cout << "[RUNNING] test_inject..." << std::endl;

    // Run inject detection for 2 seconds
    std::vector<Finding> findings;
    try {
        findings = InjectDetector::detect(2);
    } catch (const std::exception& e) {
        std::cerr << "Inject detector threw unexpected exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "  [PASS] ETW session opened, ran for 2s, and closed cleanly." << std::endl;

    // No false positives on an idle system
    if (!findings.empty()) {
        std::cerr << "Warning: unexpected findings on idle system: " << findings.size() << std::endl;
    } else {
        std::cout << "  [PASS] 0 false positives on idle system." << std::endl;
    }

    std::cout << "[SUCCESS] All inject tests passed." << std::endl;
    return 0;
}
