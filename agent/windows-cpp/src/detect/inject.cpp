#include "detect/inject.hpp"
#include "errors.hpp"
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <thread>
#include <atomic>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

namespace jocky {

static const GUID KernelProcessGuid = 
{ 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

static const GUID TiGuid = 
{ 0xF4E1897C, 0xBB5D, 0x4668, { 0xB1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 } };

static std::atomic<bool> g_keep_running(true);
static std::vector<Finding> g_findings;

void WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (!g_keep_running) return;
    if (IsEqualGUID(pEventRecord->EventHeader.ProviderId, TiGuid)) {
        // Event processing logic goes here.
    }
}

std::vector<Finding> InjectDetector::detect(int duration_seconds) {
    g_findings.clear();
    g_keep_running = true;

    TRACEHANDLE hSession = 0;
    std::wstring sessionName = L"JockyInjectTraceSession";
    
    const size_t bufSize = sizeof(EVENT_TRACE_PROPERTIES) + (sessionName.size() + 1) * sizeof(wchar_t);
    std::vector<uint8_t> propertiesBuf(bufSize, 0);
    PEVENT_TRACE_PROPERTIES pProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(propertiesBuf.data());

    pProperties->Wnode.BufferSize = (ULONG)bufSize;
    pProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProperties->Wnode.ClientContext = 1;
    pProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, sessionName.c_str(), pProperties, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTraceW(&hSession, sessionName.c_str(), pProperties);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ACCESS_DENIED) {
            return g_findings; 
        }
        throw DetectionError("StartTrace failed: " + std::to_string(status));
    }

    EnableTraceEx2(hSession, &KernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    EnableTraceEx2(hSession, &TiGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);

    EVENT_TRACE_LOGFILEW logFile = { 0 };
    logFile.LoggerName = const_cast<LPWSTR>(sessionName.c_str());
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;

    TRACEHANDLE hTrace = OpenTraceW(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(hSession, sessionName.c_str(), pProperties, EVENT_TRACE_CONTROL_STOP);
        throw DetectionError("OpenTrace failed");
    }

    std::thread traceThread([hTrace]() {
        TRACEHANDLE t = hTrace;
        ProcessTrace(&t, 1, 0, 0);
    });

    std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
    g_keep_running = false;

    ControlTraceW(hSession, sessionName.c_str(), pProperties, EVENT_TRACE_CONTROL_STOP);
    CloseTrace(hTrace);
    
    if (traceThread.joinable()) {
        traceThread.join();
    }

    return g_findings;
}

} // namespace jocky
