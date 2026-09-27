#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace jocky {

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

struct Finding {
    Severity severity;
    std::string title;
    std::string evidence;
    std::string mitre;
};

void to_json(nlohmann::json& j, const Finding& f);

void print_json(const nlohmann::json& j);

} // namespace jocky
