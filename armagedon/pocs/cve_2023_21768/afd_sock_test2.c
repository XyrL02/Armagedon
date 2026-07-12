#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ws2_32.lib")

static HANDLE hLog;
static void Log(const char *msg) {
    DWORD n; WriteFile(hLog, msg, (DWORD)strlen(msg), &n, NULL);
    WriteFile(hLog, "\r\n", 2, &n, NULL);
}

typedef struct _AFD_DATA {
    HANDLE  hIocp;
    PVOID   regInfos;
    PVOID   compEntries;
    PVOID   recvCount;
    DWORD   regCount;
    DWORD   timeout;
    DWORD   compCount;
} AFD_DATA;

typedef NTSTATUS (NTAPI *pNtDIC)(HANDLE, HANDLE, PVOID, PVOID, IO_STATUS_BLOCK*, ULONG, PVOID, ULONG, PVOID, ULONG);

int main() {
    char buf[256];
    hLog = CreateFileA("C:\\Users\\ross\\Desktop\\afd_sock_test2.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hLog || hLog == INVALID_HANDLE_VALUE) return 1;
    
    HMODULE ntdll = GetModuleHandleA("ntdll");
    pNtDIC NtDIC = (pNtDIC)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    if (!NtDIC) { Log("NtDIC fail"); CloseHandle(hLog); return 1; }
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { Log("WSA fail"); CloseHandle(hLog); return 1; }
    Log("[start] OK");
    
    // Test 0x1207B with larger buffer sizes
    {
        HANDLE hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        HANDLE hAssoc = CreateIoCompletionPort((HANDLE)s, hIocp, (ULONG_PTR)s, 0);
        
        AFD_DATA data = {0};
        data.hIocp = hIocp;
        data.regInfos = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        data.compEntries = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        data.recvCount = (PVOID)0x4141414141414141;
        data.regCount = 1;
        data.timeout = 0x1000;
        data.compCount = 8;
        
        ULONG sizes[] = { 0x30, 0x40, 0x50, 0x60, 0x80, 0xA0, 0x100, 0x200, 0x400, 0x1000 };
        for (int si = 0; si < sizeof(sizes)/sizeof(ULONG); si++) {
            memset(&data, 0, sizeof(data)); // zero struct
            data.hIocp = hIocp;
            data.regInfos = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
            data.compEntries = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
            data.recvCount = (PVOID)0x4141414141414141ULL;
            data.regCount = 1;
            data.timeout = 0x1000;
            data.compCount = 8;
            
            // Allocate a larger buffer
            char *bigBuf = (char*)VirtualAlloc(NULL, sizes[si], MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
            if (!bigBuf) { sprintf(buf, "[0x1207b][sz=0x%02lx] VAlloc fail", sizes[si]); Log(buf); continue; }
            memcpy(bigBuf, &data, min(sizes[si], sizeof(AFD_DATA)));
            
            IO_STATUS_BLOCK ios = {0};
            NTSTATUS st = NtDIC((HANDLE)s, NULL, NULL, NULL, &ios, 0x1207B, bigBuf, sizes[si], bigBuf, sizes[si]);
            sprintf(buf, "[0x1207b][sz=0x%02lx] st=0x%08lx ios=0x%08lx", sizes[si], st, ios.Status);
            Log(buf);
            
            // Check output buffer content
            sprintf(buf, "  output[0..15]: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                (BYTE)bigBuf[0],(BYTE)bigBuf[1],(BYTE)bigBuf[2],(BYTE)bigBuf[3],
                (BYTE)bigBuf[4],(BYTE)bigBuf[5],(BYTE)bigBuf[6],(BYTE)bigBuf[7],
                (BYTE)bigBuf[8],(BYTE)bigBuf[9],(BYTE)bigBuf[10],(BYTE)bigBuf[11],
                (BYTE)bigBuf[12],(BYTE)bigBuf[13],(BYTE)bigBuf[14],(BYTE)bigBuf[15]);
            Log(buf);
            
            VirtualFree(bigBuf, 0, MEM_RELEASE);
            VirtualFree(data.regInfos, 0, MEM_RELEASE);
            VirtualFree(data.compEntries, 0, MEM_RELEASE);
        }
        
        closesocket(s);
        CloseHandle(hIocp);
    }
    
    // Test 0x12047 with IOCP + socket
    {
        Log("--- 0x12047 testing ---");
        HANDLE hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        HANDLE hAssoc = CreateIoCompletionPort((HANDLE)s, hIocp, (ULONG_PTR)s, 0);
        
        char bufIn[0x100] = {0};
        char bufOut[0x100] = {0};
        IO_STATUS_BLOCK ios = {0};
        NTSTATUS st = NtDIC((HANDLE)s, NULL, NULL, NULL, &ios, 0x12047, bufIn, sizeof(bufIn), bufOut, sizeof(bufOut));
        sprintf(buf, "[0x12047] st=0x%08lx ios=0x%08lx", st, ios.Status); Log(buf);
        
        // Check output
        int changed = 0;
        for (int i = 0; i < 32; i++) if (bufOut[i] != 0) changed = 1;
        if (changed) {
            sprintf(buf, "  output changed bytes at:");
            for (int i = 0; i < 32; i++) if (bufOut[i]) { char t[64]; sprintf(t, " [%d]=0x%02x", i, (BYTE)bufOut[i]); strcat(buf, t); }
            Log(buf);
        } else {
            Log("  output all zeros");
        }
        
        closesocket(s);
        CloseHandle(hIocp);
    }
    
    // Test 0x12047 without IOCP / without socket
    {
        Log("--- 0x12047 on direct NtCreateFile to \\Device\\Afd\\Endpoint ---");
        UNICODE_STRING us;
        RtlInitUnicodeString(&us, L"\\Device\\Afd\\Endpoint");
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
        
        HANDLE hEp = NULL;
        IO_STATUS_BLOCK ios = {0};
        NTSTATUS st = NtCreateFile(&hEp, MAXIMUM_ALLOWED, &oa, &ios, NULL, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
        sprintf(buf, "NtCreateFile st=0x%08lx", st); Log(buf);
        
        if (NT_SUCCESS(st)) {
            char bufIn[0x100] = {0};
            char bufOut[0x100] = {0};
            memset(&ios, 0, sizeof(ios));
            st = NtDIC(hEp, NULL, NULL, NULL, &ios, 0x12047, bufIn, sizeof(bufIn), bufOut, sizeof(bufOut));
            sprintf(buf, "[0x12047 via NtCF] st=0x%08lx ios=0x%08lx", st, ios.Status); Log(buf);
            CloseHandle(hEp);
        }
    }
    
    Log("[end]");
    WSACleanup();
    CloseHandle(hLog);
    return 0;
}
