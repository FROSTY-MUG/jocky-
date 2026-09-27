#pragma once
#include <string>

namespace jocky {

class ModuleLoader {
public:
    static int load_and_run(const std::string& jkm_path, const std::string& b64_pubkey);
};

} // namespace jocky
