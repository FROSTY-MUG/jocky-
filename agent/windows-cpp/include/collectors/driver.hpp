#pragma once
#include <nlohmann/json.hpp>

namespace jocky {

class DriverCollector {
public:
    static nlohmann::json collect();
};

} // namespace jocky
