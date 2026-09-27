#include "consent.hpp"
#include "errors.hpp"
#include <iostream>
#include <cstdlib>
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <fstream>
#include <filesystem>

using namespace jocky;

static std::string run_cmd(const std::string& cmd) {
    std::array<char, 256> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
    if (!pipe) {
        throw std::runtime_error("popen failed: " + cmd);
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    while (!result.empty() && (result.back() == '\r' || result.back() == '\n' || result.back() == ' ')) {
        result.pop_back();
    }
    return result;
}

int main() {
    std::cout << "[RUNNING] test_consent..." << std::endl;

    for (const char* candidate : {"../../..", "../..", "..", "."}) {
        if (std::filesystem::exists(std::string(candidate) + "/Cargo.lock")) {
            std::filesystem::current_path(candidate);
            break;
        }
    }

    // Ensure scratch directory and key exists
    CreateDirectoryA("scratch", NULL);
    std::string key_path = "scratch\\test_consent_agent.key";
    std::string pub_path = "scratch\\test_consent_agent.pub";

    std::ifstream kf(key_path);
    if (!kf.good()) {
        std::string keygen_cmd = "cargo run -p jockyc -- keygen --out " + key_path;
        run_cmd(keygen_cmd);
    }

    std::string issue_bin = "target\\debug\\jocky-token-issue.exe";
    std::ifstream ib(issue_bin);
    if (!ib.good()) {
        issue_bin = "target\\release\\jocky-token-issue.exe";
    }

    // Read pubkey file
    std::ifstream pf(pub_path);
    std::string pubkey_content((std::istreambuf_iterator<char>(pf)), std::istreambuf_iterator<char>());
    std::string b64_pubkey = "";
    DWORD b64_len = 0;
    if (CryptBinaryToStringA(reinterpret_cast<const BYTE*>(pubkey_content.data()), static_cast<DWORD>(pubkey_content.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64_len)) {
        std::vector<char> buf(b64_len);
        if (CryptBinaryToStringA(reinterpret_cast<const BYTE*>(pubkey_content.data()), static_cast<DWORD>(pubkey_content.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buf.data(), &b64_len)) {
            b64_pubkey = std::string(buf.data());
        }
    }
    if (b64_pubkey.empty()) {
        std::cerr << "Failed to encode pubkey" << std::endl;
        return 1;
    }

    // 1. Valid token -> success
    std::string issue_cmd = issue_bin + " --key " + key_path + " --agent-id test-agent-01 --scope host:LAB-WIN-01 --ttl-seconds 3600 --max-ops 1000 --policy-version 1";
    std::string valid_token = run_cmd(issue_cmd);
    if (valid_token.empty()) {
        std::cerr << "Failed to generate valid token" << std::endl;
        return 1;
    }

    bool valid_passed = false;
    try {
        ConsentValidator::verify(valid_token, b64_pubkey);
        valid_passed = true;
    } catch (const std::exception& e) {
        std::cerr << "Valid token failed: " << e.what() << std::endl;
    }
    if (!valid_passed) {
        std::cerr << "Valid token verification failed" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Valid token accepted." << std::endl;

    // 2. Missing env var -> throws ConsentError
    _putenv("JOCKY_CONSENT_TOKEN=");
    _putenv("JOCKY_MANAGER_PUBKEY=");
    bool missing_env_threw = false;
    try {
        ConsentValidator::verify_from_env();
    } catch (const ConsentError&) {
        missing_env_threw = true;
    }
    if (!missing_env_threw) {
        std::cerr << "Missing env var did not throw" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Missing env var rejected." << std::endl;

    // 3. Malformed base64 -> throws ConsentError
    bool malformed_threw = false;
    try {
        ConsentValidator::verify("!not-valid-base64!", b64_pubkey);
    } catch (const ConsentError&) {
        malformed_threw = true;
    }
    if (!malformed_threw) {
        std::cerr << "Malformed base64 did not throw" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Malformed base64 rejected." << std::endl;

    // 4. Tampered token -> throws ConsentError
    std::string tampered_token = valid_token;
    if (tampered_token.size() > 20) {
        tampered_token[15] = (tampered_token[15] == 'A') ? 'B' : 'A';
    }
    bool tampered_threw = false;
    try {
        ConsentValidator::verify(tampered_token, b64_pubkey);
    } catch (const ConsentError&) {
        tampered_threw = true;
    }
    if (!tampered_threw) {
        std::cerr << "Tampered token did not throw" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Tampered token rejected." << std::endl;

    // 5. Expired token -> throws ConsentError
    // Issue token with minimal 1s TTL and sleep 1500ms
    std::string short_cmd = issue_bin + " --key " + key_path + " --agent-id test-agent-01 --scope host:LAB-WIN-01 --ttl-seconds 1 --max-ops 1000 --policy-version 1";
    std::string short_token = run_cmd(short_cmd);
    Sleep(1500);

    bool expired_threw = false;
    try {
        ConsentValidator::verify(short_token, b64_pubkey);
    } catch (const ConsentError&) {
        expired_threw = true;
    }
    if (!expired_threw) {
        std::cerr << "Expired token did not throw" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Expired token rejected." << std::endl;

    std::cout << "[SUCCESS] All consent tests passed." << std::endl;
    return 0;
}
