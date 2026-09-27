#include "collectors/process.hpp"
#include "collectors/network.hpp"
#include "collectors/driver.hpp"
#include <iostream>
#include <cassert>

using namespace jocky;

int main() {
    std::cout << "[RUNNING] test_collectors..." << std::endl;

    // 1. Process collector returns > 0 processes, each with non-empty name
    nlohmann::json procs = ProcessCollector::collect();
    if (!procs.is_array() || procs.empty()) {
        std::cerr << "Process collector returned empty or non-array" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Process collector returned " << procs.size() << " processes." << std::endl;

    for (const auto& proc : procs) {
        if (!proc.contains("name") || !proc["name"].is_string() || proc["name"].get<std::string>().empty() || !proc.contains("pid")) {
            std::cerr << "Process missing name or PID" << std::endl;
            return 1;
        }
    }
    std::cout << "  [PASS] All processes have valid PID and non-empty name." << std::endl;

    // 2. Network collector returns a list (may be empty on some test environments, but valid array)
    nlohmann::json net = NetworkCollector::collect();
    if (!net.is_array()) {
        std::cerr << "Network collector did not return an array" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Network collector returned array with " << net.size() << " connections." << std::endl;

    // 3. Driver collector returns > 0 drivers
    nlohmann::json drivers = DriverCollector::collect();
    if (!drivers.is_array() || drivers.empty()) {
        std::cerr << "Driver collector returned empty or non-array" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Driver collector returned " << drivers.size() << " drivers." << std::endl;

    std::cout << "[SUCCESS] All collector tests passed." << std::endl;
    return 0;
}
