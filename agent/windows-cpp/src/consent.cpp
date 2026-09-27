#include "consent.hpp"
#include "errors.hpp"
#include "jocky.h"
#include <windows.h>
#include <wincrypt.h>
#include <cstdlib>
#include <sstream>

namespace jocky {

std::vector<uint8_t> ConsentValidator::decode_base64(const std::string& b64) {
    DWORD out_len = 0;
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64_ANY, NULL, &out_len, NULL, NULL)) {
        throw ConsentError("Failed to decode base64");
    }
    std::vector<uint8_t> out(out_len);
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64_ANY, out.data(), &out_len, NULL, NULL)) {
        throw ConsentError("Failed to decode base64");
    }
    return out;
}

static bool extract_hex_pubkey(const std::string& s, std::vector<uint8_t>& out) {
    std::string hex;
    std::istringstream stream(s);
    std::string line;
    while (std::getline(stream, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\n' || line.back() == '\t')) {
            line.pop_back();
        }
        if (!line.empty() && line.rfind("-----", 0) != 0) {
            hex += line;
        }
    }
    if (hex.size() == 64) {
        bool all_hex = true;
        for (char c : hex) {
            if (!isxdigit(static_cast<unsigned char>(c))) {
                all_hex = false;
                break;
            }
        }
        if (all_hex) {
            out.clear();
            out.reserve(32);
            for (size_t i = 0; i < 64; i += 2) {
                std::string byte_str = hex.substr(i, 2);
                out.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            }
            return true;
        }
    }
    return false;
}

std::vector<uint8_t> ConsentValidator::decode_pubkey(const std::string& b64_pubkey) {
    // 1. Direct PEM or 64-hex string
    std::vector<uint8_t> raw_32;
    if (extract_hex_pubkey(b64_pubkey, raw_32)) {
        return raw_32;
    }

    // 2. Base64 decoded
    try {
        auto pubkey_bytes = decode_base64(b64_pubkey);
        if (pubkey_bytes.size() == 32) {
            return pubkey_bytes;
        }
        std::string s(reinterpret_cast<char*>(pubkey_bytes.data()), pubkey_bytes.size());
        if (extract_hex_pubkey(s, raw_32)) {
            return raw_32;
        }
    } catch (...) {}

    throw ConsentError("Public key must be exactly 32 bytes");
}

void ConsentValidator::verify(const std::string& b64_token, const std::string& b64_pubkey) {
    auto token_bytes = decode_base64(b64_token);
    auto pubkey_bytes = decode_pubkey(b64_pubkey);

    int32_t res = jocky_consent_token_verify(
        token_bytes.data(), token_bytes.size(),
        pubkey_bytes.data(), pubkey_bytes.size()
    );

    if (res != 0) {
        char* err_ptr = jocky_last_error();
        std::string err_msg = err_ptr ? std::string(err_ptr) : "Unknown error in Rust FFI";
        if (err_ptr) {
            jocky_free_string(err_ptr);
        }
        throw ConsentError("Consent Verification Failed: " + err_msg);
    }
}

void ConsentValidator::verify_from_env() {
    const char* token_env = std::getenv("JOCKY_CONSENT_TOKEN");
    const char* pubkey_env = std::getenv("JOCKY_MANAGER_PUBKEY");

    if (!token_env || !pubkey_env) {
        throw ConsentError("Missing JOCKY_CONSENT_TOKEN or JOCKY_MANAGER_PUBKEY in environment");
    }

    verify(token_env, pubkey_env);
}

} // namespace jocky
