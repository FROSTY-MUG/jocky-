#include "output.hpp"
#include <iostream>

namespace jocky {

void to_json(nlohmann::json& j, const Finding& f) {
    std::string sev_str;
    switch (f.severity) {
        case Severity::Info: sev_str = "Info"; break;
        case Severity::Low: sev_str = "Low"; break;
        case Severity::Medium: sev_str = "Medium"; break;
        case Severity::High: sev_str = "High"; break;
        case Severity::Critical: sev_str = "Critical"; break;
    }
    j = nlohmann::json{
        {"severity", sev_str},
        {"title", f.title},
        {"evidence", f.evidence},
        {"mitre", f.mitre}
    };
}

void print_json(const nlohmann::json& j) {
    std::cout << j.dump(2) << std::endl;
}

} // namespace jocky
