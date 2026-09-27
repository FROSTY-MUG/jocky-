#pragma once
#include <string>
#include <vector>

namespace jocky {

class ConsentValidator {
public:
    static void verify_from_env();
    static void verify(const std::string& b64_token, const std::string& b64_pubkey);
    static std::vector<uint8_t> decode_base64(const std::string& b64);
    static std::vector<uint8_t> decode_pubkey(const std::string& b64_pubkey);
};

} // namespace jocky
