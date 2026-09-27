#include "module_loader.hpp"
#include "errors.hpp"
#include "consent.hpp"
#include "jocky.h"
#include <windows.h>
#include <fstream>
#include <vector>
#include <cstring>

namespace jocky {

int ModuleLoader::load_and_run(const std::string& jkm_path, const std::string& b64_pubkey) {
    auto pubkey_bytes = ConsentValidator::decode_pubkey(b64_pubkey);

    std::ifstream file(jkm_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw ModuleLoadError("Failed to open module file: " + jkm_path);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> jkm_bytes(size);
    if (!file.read(reinterpret_cast<char*>(jkm_bytes.data()), size)) {
        throw ModuleLoadError("Failed to read module file");
    }

    int32_t res = jocky_jkm_verify(
        jkm_bytes.data(), jkm_bytes.size(),
        pubkey_bytes.data(), pubkey_bytes.size()
    );

    if (res != 0) {
        char* err_ptr = jocky_last_error();
        std::string err_msg = err_ptr ? std::string(err_ptr) : "Unknown error verifying module";
        if (err_ptr) {
            jocky_free_string(err_ptr);
        }
        throw ModuleLoadError("Module verification failed: " + err_msg);
    }

    if (jkm_bytes.size() < 64) {
        throw ModuleLoadError("JKM file too small");
    }

    uint32_t code_offset = 0;
    std::memcpy(&code_offset, &jkm_bytes[16], sizeof(uint32_t));
    uint32_t code_len = 0;
    std::memcpy(&code_len, &jkm_bytes[20], sizeof(uint32_t));

    if (code_offset + code_len > jkm_bytes.size()) {
        throw ModuleLoadError("Code section out of bounds");
    }

    const uint8_t* exec_code = &jkm_bytes[code_offset];
    size_t exec_len = code_len;

    // Check if code section is a COFF object file (.obj)
    if (code_len >= sizeof(IMAGE_FILE_HEADER)) {
        const IMAGE_FILE_HEADER* coff = reinterpret_cast<const IMAGE_FILE_HEADER*>(exec_code);
        if (coff->Machine == IMAGE_FILE_MACHINE_AMD64 || coff->Machine == IMAGE_FILE_MACHINE_I386) {
            size_t sec_offset = sizeof(IMAGE_FILE_HEADER) + coff->SizeOfOptionalHeader;
            for (WORD i = 0; i < coff->NumberOfSections; ++i) {
                if (sec_offset + sizeof(IMAGE_SECTION_HEADER) <= code_len) {
                    const IMAGE_SECTION_HEADER* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(exec_code + sec_offset);
                    if (std::strncmp(reinterpret_cast<const char*>(sec->Name), ".text", 5) == 0) {
                        if (sec->PointerToRawData + sec->SizeOfRawData <= code_len) {
                            exec_code = exec_code + sec->PointerToRawData;
                            exec_len = sec->SizeOfRawData;
                            break;
                        }
                    }
                    sec_offset += sizeof(IMAGE_SECTION_HEADER);
                }
            }
        }
    }

    void* mem = VirtualAlloc(NULL, exec_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        throw ModuleLoadError("VirtualAlloc failed");
    }

    std::memcpy(mem, exec_code, exec_len);

    DWORD old_protect;
    if (!VirtualProtect(mem, exec_len, PAGE_EXECUTE_READ, &old_protect)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        throw ModuleLoadError("VirtualProtect to PAGE_EXECUTE_READ failed");
    }

    using EntryPoint = int(*)();
    EntryPoint entry = reinterpret_cast<EntryPoint>(mem);

    int result = entry();

    VirtualFree(mem, 0, MEM_RELEASE);

    return result;
}

} // namespace jocky
