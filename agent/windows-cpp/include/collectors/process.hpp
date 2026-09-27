#pragma once
#include <nlohmann/json.hpp>

namespace jocky {

class ProcessCollector {
public:
    static nlohmann::json collect();
};

} // namespace jocky
