#pragma once
#include <nlohmann/json.hpp>

namespace jocky {

class NetworkCollector {
public:
    static nlohmann::json collect();
};

} // namespace jocky
