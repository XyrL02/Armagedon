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
    hLog = CreateFileA("C:\\Users\\ross\\Desktop\\afd_sock_test.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hLog || hLog == INVALID_HANDLE_VALUE) return 1;
    
    HMODULE ntdll = GetModuleHandleA("ntdll");
    pNtDIC NtDIC = (pNtDIC)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    if (!NtDIC) { Log("NtDIC fail"); CloseHandle(hLog); return 1; }
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { Log("WSA fail"); CloseHandle(hLog); return 1; }
    Log("[start] OK");
    
    // Test multiple IOCTL codes on socket handle
    ULONG iocals[] = { 0x1203B, 0x1204F, 0x1205B, 0x1207B, 0x1207F, 0x120C3, 0x12127, 0x1208F, 0x12017, 0x1212B, 0x12047, 0x12093, 0x120BB, 0x120BF, 0x1201B };
    ULONG bufSizes[] = { sizeof(AFD_DATA), 0x30, 0x28, 0x2C, 0x20, 0x18 };
    
    for (int ii = 0; ii < sizeof(iocals)/sizeof(ULONG); ii++) {
        // Create IOCP
        HANDLE hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (!hIocp) {
            sprintf(buf, "[0x%05lx] IOCP fail: %lu", iocals[ii], GetLastError()); Log(buf); continue;
        }
        
        // Create socket
        SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (s == INVALID_SOCKET) {
            sprintf(buf, "[0x%05lx] socket fail: %d", iocals[ii], WSAGetLastError()); Log(buf);
            CloseHandle(hIocp); continue;
        }
        
        // Associate with IOCP
        HANDLE hAssoc = CreateIoCompletionPort((HANDLE)s, hIocp, (ULONG_PTR)s, 0);
        if (!hAssoc) {
            sprintf(buf, "[0x%05lx] assoc fail: %lu", iocals[ii], GetLastError()); Log(buf);
            closesocket(s); CloseHandle(hIocp); continue;
        }
        
        // Try each buffer size
        for (int si = 0; si < sizeof(bufSizes)/sizeof(ULONG); si++) {
            AFD_DATA data = {0};
            data.hIocp = hIocp;
            data.regInfos = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
            data.compEntries = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
            data.recvCount = (PVOID)0x4141414141414141;
            data.regCount = 1;
            data.timeout = 0x1000;
            data.compCount = 8;
            
            if (!data.regInfos || !data.compEntries) {
                sprintf(buf, "[0x%05lx][sz=0x%02lx] VAlloc fail", iocals[ii], bufSizes[si]); Log(buf);
                continue;
            }
            
            IO_STATUS_BLOCK ios = {0};
            NTSTATUS st = NtDIC((HANDLE)s, NULL, NULL, NULL, &ios, iocals[ii], &data, bufSizes[si], NULL, 0);
            sprintf(buf, "[0x%05lx][sz=0x%02lx] st=0x%08lx ios=0x%08lx", iocals[ii], bufSizes[si], st, ios.Status);
            Log(buf);
            
            VirtualFree(data.regInfos, 0, MEM_RELEASE);
            VirtualFree(data.compEntries, 0, MEM_RELEASE);
        }
        
        closesocket(s);
        CloseHandle(hIocp);
    }
    
    WSACleanup();
    CloseHandle(hLog);
    return 0;
}
