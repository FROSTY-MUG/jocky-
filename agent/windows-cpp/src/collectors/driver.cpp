#include "collectors/driver.hpp"
#include "errors.hpp"
#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace jocky {

std::string compute_sha256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return "";

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return "";

    DWORD cbHashObject = 0, cbData = 0, cbHash = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);

    std::vector<uint8_t> hashObject(cbHashObject);
    std::vector<uint8_t> hash(cbHash);

    status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        BCryptHashData(hHash, (PBYTE)buffer, (ULONG)file.gcount(), 0);
    }
    if (file.gcount() > 0) {
        BCryptHashData(hHash, (PBYTE)buffer, (ULONG)file.gcount(), 0);
    }

    BCryptFinishHash(hHash, hash.data(), cbHash, 0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::stringstream ss;
    for (DWORD i = 0; i < cbHash; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

nlohmann::json DriverCollector::collect() {
    nlohmann::json result = nlohmann::json::array();
    LPVOID drivers[1024];
    DWORD cbNeeded;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        int cDrivers = cbNeeded / sizeof(drivers[0]);
        for (int i = 0; i < cDrivers; i++) {
            char name[256];
            char path[MAX_PATH];

            if (GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name)) && 
                GetDeviceDriverFileNameA(drivers[i], path, sizeof(path))) {
                
                std::string path_str = path;
                if (path_str.find("\\SystemRoot\\") == 0) {
                    char winDir[MAX_PATH];
                    GetWindowsDirectoryA(winDir, MAX_PATH);
                    path_str = std::string(winDir) + "\\" + path_str.substr(12);
                } else if (path_str.find("\\??\\") == 0) {
                    path_str = path_str.substr(4);
                }

                std::string sha256 = compute_sha256(path_str);
                
                result.push_back({
                    {"base", (uint64_t)drivers[i]},
                    {"name", name},
                    {"path", path_str},
                    {"sha256", sha256}
                });
            }
        }
    }
    return result;
}

} // namespace jocky
