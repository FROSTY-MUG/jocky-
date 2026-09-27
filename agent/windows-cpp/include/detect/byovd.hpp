#pragma once
#include <nlohmann/json.hpp>
#include "output.hpp"
#include <vector>
#include <string>

namespace jocky {

class ByovdDetector {
public:
    static std::vector<Finding> detect();
    static std::vector<Finding> check_driver_hashes(const nlohmann::json& drivers, const std::string& blocklist_path = "");
};

} // namespace jocky
