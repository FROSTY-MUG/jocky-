#include "module_loader.hpp"
#include "errors.hpp"
#include <iostream>
#include <windows.h>
#include <wincrypt.h>
#include <fstream>
#include <vector>
#include <string>
#include <array>
#include <memory>
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
    return result;
}

int main() {
    std::cout << "[RUNNING] test_module_loader..." << std::endl;

    for (const char* candidate : {"../../..", "../..", "..", "."}) {
        if (std::filesystem::exists(std::string(candidate) + "/Cargo.lock")) {
            std::filesystem::current_path(candidate);
            break;
        }
    }

    CreateDirectoryA("scratch", NULL);

    // Ensure min.jky exists
    std::string min_jky_path = "scratch\\min.jky";
    if (!std::filesystem::exists(min_jky_path)) {
        std::ofstream jky(min_jky_path);
        jky << "fn main() -> i32 {\n    return 42;\n}\n";
    }

    std::string key_path = "scratch\\agent-test.key";
    std::string pub_path = "scratch\\agent-test.pub";
    std::string jkm_path = "scratch\\min.jkm";

    // Ensure key exists
    std::ifstream kf(key_path);
    if (!kf.good()) {
        run_cmd("cargo run -p jockyc -- keygen --out " + key_path);
    }

    // Ensure min.jkm exists
    std::ifstream jf(jkm_path);
    if (!jf.good()) {
        run_cmd("cargo run -p jockyc -- build scratch\\min.jky --target x86_64-pc-windows-msvc --sign --key " + key_path + " --out " + jkm_path);
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
        std::cerr << "Failed to encode public key" << std::endl;
        return 1;
    }

    // 1. Valid .jkm -> returns 42
    int ret = -1;
    bool load_succeeded = false;
    try {
        ret = ModuleLoader::load_and_run(jkm_path, b64_pubkey);
        load_succeeded = true;
    } catch (const std::exception& e) {
        std::cerr << "Module load failed: " << e.what() << std::endl;
    }
    if (!load_succeeded || ret != 42) {
        std::cerr << "Failed: module execution returned " << ret << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Real .jkm loaded and executed successfully, returned: " << ret << std::endl;

    // 2. Load with wrong pubkey -> fails
    std::string wrong_key_path = "scratch\\wrong-key.key";
    std::string wrong_pub_path = "scratch\\wrong-key.pub";
    std::ifstream wkf(wrong_key_path);
    if (!wkf.good()) {
        run_cmd("cargo run -p jockyc -- keygen --out " + wrong_key_path);
    }
    std::ifstream wpf(wrong_pub_path);
    std::string wrong_pub_content((std::istreambuf_iterator<char>(wpf)), std::istreambuf_iterator<char>());
    std::string b64_wrong_pubkey = "";
    DWORD w_b64_len = 0;
    if (CryptBinaryToStringA(reinterpret_cast<const BYTE*>(wrong_pub_content.data()), static_cast<DWORD>(wrong_pub_content.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &w_b64_len)) {
        std::vector<char> buf(w_b64_len);
        if (CryptBinaryToStringA(reinterpret_cast<const BYTE*>(wrong_pub_content.data()), static_cast<DWORD>(wrong_pub_content.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buf.data(), &w_b64_len)) {
            b64_wrong_pubkey = std::string(buf.data());
        }
    }

    bool wrong_key_threw = false;
    try {
        ModuleLoader::load_and_run(jkm_path, b64_wrong_pubkey);
    } catch (const ModuleLoadError&) {
        wrong_key_threw = true;
    }
    if (!wrong_key_threw) {
        std::cerr << "Failed: wrong pubkey did not throw" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Wrong pubkey rejected." << std::endl;

    // 3. Load a tampered .jkm -> fails
    std::string tampered_path = "scratch\\tampered_test.jkm";
    {
        std::ifstream src(jkm_path, std::ios::binary);
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
        if (data.size() <= 80) {
            std::cerr << "Invalid jkm size: " << data.size() << std::endl;
            return 1;
        }
        data[70] ^= 0xFF; // Flip a byte in the code payload
        std::ofstream dst(tampered_path, std::ios::binary);
        dst.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    bool tampered_threw = false;
    try {
        ModuleLoader::load_and_run(tampered_path, b64_pubkey);
    } catch (const ModuleLoadError&) {
        tampered_threw = true;
    }
    if (!tampered_threw) {
        std::cerr << "Failed: tampered jkm did not throw" << std::endl;
        return 1;
    }
    std::cout << "  [PASS] Tampered .jkm rejected." << std::endl;

    std::cout << "[SUCCESS] All module loader tests passed." << std::endl;
    return 0;
}
