#include "collectors/process.hpp"
#include "errors.hpp"
#include "utf8.hpp"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace jocky {

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

struct SYSTEM_PROCESS_INFORMATION_MINIMAL {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
};

nlohmann::json ProcessCollector::collect() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        throw CollectionError("Failed to get ntdll handle");
    }

    auto NtQuerySystemInformation_fn = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation_fn) {
        throw CollectionError("Failed to get NtQuerySystemInformation");
    }

    ULONG size = 1024 * 1024;
    std::vector<uint8_t> buffer(size);
    ULONG return_length = 0;

    NTSTATUS status;
    while ((status = NtQuerySystemInformation_fn(SystemProcessInformation, buffer.data(), size, &return_length)) == STATUS_INFO_LENGTH_MISMATCH) {
        size *= 2;
        buffer.resize(size);
    }

    if (!NT_SUCCESS(status)) {
        throw CollectionError("NtQuerySystemInformation failed");
    }

    nlohmann::json result = nlohmann::json::array();
    
    SYSTEM_PROCESS_INFORMATION_MINIMAL* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_MINIMAL*>(buffer.data());

    while (true) {
        DWORD pid = (DWORD)(uintptr_t)spi->UniqueProcessId;
        DWORD ppid = (DWORD)(uintptr_t)spi->InheritedFromUniqueProcessId;

        std::wstring name_w;
        if (spi->ImageName.Buffer) {
            name_w = std::wstring(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(WCHAR));
        } else if (pid == 0) {
            name_w = L"System Idle Process";
        }

        std::string name = wide_to_utf8(name_w);
        std::string path = "";

        if (pid != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hProcess) {
                WCHAR path_buf[MAX_PATH];
                DWORD path_len = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, path_buf, &path_len)) {
                    path = wide_to_utf8(std::wstring(path_buf, path_len));
                }
                CloseHandle(hProcess);
            }
        }

        result.push_back({
            {"pid", pid},
            {"ppid", ppid},
            {"name", name},
            {"path", path}
        });

        if (spi->NextEntryOffset == 0) {
            break;
        }
        spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_MINIMAL*>(
            reinterpret_cast<uint8_t*>(spi) + spi->NextEntryOffset
        );
    }

    return result;
}

} // namespace jocky
