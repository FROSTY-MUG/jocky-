#pragma once
#include <vector>
#include "output.hpp"

namespace jocky {

class InjectDetector {
public:
    static std::vector<Finding> detect(int duration_seconds);
};

} // namespace jocky
