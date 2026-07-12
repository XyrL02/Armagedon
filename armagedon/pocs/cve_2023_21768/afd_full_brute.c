/*
 * afd_full_brute.c — Sweep ALL IOCTL function codes on AFD socket handles
 * Build: x86_64-w64-mingw32-gcc afd_full_brute.c -o afd_full_brute.exe -lws2_32 -s
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

typedef NTSTATUS (NTAPI *fnNtDIC)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                  ULONG, PVOID, ULONG, PVOID, ULONG);

static fnNtDIC MyNtDIC = NULL;

static char logbuf[4096];
static HANDLE logfile = NULL;

static void Log(const char *s) {
    DWORD written;
    WriteFile(logfile, s, (DWORD)strlen(s), &written, NULL);
    WriteFile(logfile, "\r\n", 2, &written, NULL);
}

static void LogF(const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    vsnprintf(logbuf, sizeof(logbuf), fmt, va);
    va_end(va);
    Log(logbuf);
}

/* Build IOCTL: CTL_CODE(devtype, func, METHOD_NEITHER, FILE_ANY_ACCESS) */
static ULONG MakeIOCtl(USHORT devtype, USHORT func) {
    return ((ULONG)devtype << 16) | (0 << 14) | ((ULONG)func << 2) | 3;
}

/* Try one IOCTL, log if recognized (not 0xC0000010) */
static void TryIOCtl(SOCKET s, ULONG code, ULONG inSz, ULONG outSz, int detailed) {
    char inbuf[0x1000];
    char outbuf[0x1000];
    IO_STATUS_BLOCK ios = {0};
    
    memset(inbuf, 0, sizeof(inbuf));
    memset(outbuf, 0, sizeof(outbuf));
    
    NTSTATUS st = MyNtDIC((HANDLE)s, NULL, NULL, NULL, &ios, code,
                          inbuf, inSz, outbuf, outSz);
    
    if (st == STATUS_INVALID_DEVICE_REQUEST)
        return;  /* unrecognized — skip */
    
    if (detailed) {
        LogF("[0x%08lx][sz=%lu,%lu] st=0x%08lx info=%llu",
             code, inSz, outSz, st, (unsigned long long)ios.Information);
        LogF("  out: %02x %02x %02x %02x %02x %02x %02x %02x",
             (BYTE)outbuf[0], (BYTE)outbuf[1], (BYTE)outbuf[2], (BYTE)outbuf[3],
             (BYTE)outbuf[4], (BYTE)outbuf[5], (BYTE)outbuf[6], (BYTE)outbuf[7]);
        LogF("  in:  %02x %02x %02x %02x %02x %02x %02x %02x",
             (BYTE)inbuf[0],  (BYTE)inbuf[1],  (BYTE)inbuf[2],  (BYTE)inbuf[3],
             (BYTE)inbuf[4],  (BYTE)inbuf[5],  (BYTE)inbuf[6],  (BYTE)inbuf[7]);
    } else {
        LogF("  [code=0x%08lx] st=0x%08lx info=%llu",
             code, st, (unsigned long long)ios.Information);
    }
}

/* Detailed test of a specific code with many buffer sizes */
static void DetailIOCtl(SOCKET s, ULONG code, USHORT func, USHORT devtype) {
    ULONG sizes[] = {0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50,
                     0x60, 0x70, 0x80, 0x90, 0xA0, 0xC0, 0x100, 0x200,
                     0x400, 0x800, 0x1000};
    int nsizes = sizeof(sizes)/sizeof(sizes[0]);
    
    LogF("\n=== DETAIL: dev=0x%04x func=0x%03x code=0x%08lx ===",
         devtype, func, code);
    
    for (int i = 0; i < nsizes; i++) {
        for (int j = 0; j < nsizes; j++) {
            TryIOCtl(s, code, sizes[i], sizes[j], 1);
        }
    }
}

int main() {
    logfile = CreateFileA("C:\\Users\\ross\\Desktop\\afd_brute_log.txt",
                          GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!logfile) { printf("[!] Log FAIL\n"); return 1; }
    
    Log("=== AFD FULL IOCTL BRUTE FORCE ===");
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    MyNtDIC = (fnNtDIC)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    if (!MyNtDIC) { Log("[!] NtDIC FAIL"); CloseHandle(logfile); return 1; }
    
    /* Socket setup */
    WSADATA wsd;
    WSAStartup(MAKEWORD(2,2), &wsd);
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                          WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) { Log("[!] WSASocket FAIL"); return 1; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 1);
    Log("[+] Socket bound+listening");
    
    /* ========== PHASE 1: RAPID SWEEP ==========
       Test ALL 8192 IOCTL codes with buffer size 0x30.
       Device types: 1 (BEEP matches 0x12127) and 0x1200 (NETWORK)
    */
    
    /* Device type 1 sweep */
    Log("\n=== PHASE 1: Device type 1 (funcs 0x000-0xFFF) ===");
    int found_dev1[0x1000] = {0};
    int nfound1 = 0;
    for (USHORT func = 0; func < 0x1000; func++) {
        ULONG code = MakeIOCtl(1, func);
        char inbuf[0x30], outbuf[0x30];
        IO_STATUS_BLOCK ios = {0};
        memset(inbuf, 0, sizeof(inbuf));
        memset(outbuf, 0, sizeof(outbuf));
        NTSTATUS st = MyNtDIC((HANDLE)s, NULL, NULL, NULL, &ios, code,
                              inbuf, 0x30, outbuf, 0x30);
        if (st != STATUS_INVALID_DEVICE_REQUEST) {
            found_dev1[func] = 1;
            nfound1++;
            LogF("[PHASE1 dev=1 func=0x%03x code=0x%08lx] st=0x%08lx out[0]=%02x",
                 func, code, st, (BYTE)outbuf[0]);
        }
        if (func % 256 == 255)
            LogF("  progress dev=1: %u/4095", func+1);
    }
    LogF("[PHASE1 dev=1] TOTAL RECOGNIZED: %d", nfound1);
    
    /* Device type 0x1200 sweep */
    Log("\n=== PHASE 1: Device type 0x1200 (funcs 0x000-0xFFF) ===");
    int found_dev1200[0x1000] = {0};
    int nfound1200 = 0;
    for (USHORT func = 0; func < 0x1000; func++) {
        ULONG code = MakeIOCtl(0x1200, func);
        char inbuf[0x30], outbuf[0x30];
        IO_STATUS_BLOCK ios = {0};
        memset(inbuf, 0, sizeof(inbuf));
        memset(outbuf, 0, sizeof(outbuf));
        NTSTATUS st = MyNtDIC((HANDLE)s, NULL, NULL, NULL, &ios, code,
                              inbuf, 0x30, outbuf, 0x30);
        if (st != STATUS_INVALID_DEVICE_REQUEST) {
            found_dev1200[func] = 1;
            nfound1200++;
            LogF("[PHASE1 dev=0x1200 func=0x%03x code=0x%08lx] st=0x%08lx out[0]=%02x",
                 func, code, st, (BYTE)outbuf[0]);
        }
        if (func % 256 == 255)
            LogF("  progress dev=0x1200: %u/4095", func+1);
    }
    LogF("[PHASE1 dev=0x1200] TOTAL RECOGNIZED: %d", nfound1200);
    
    /* ========== PHASE 2: DETAILED TEST of recognized codes ==========
       For each recognized code, try multiple buffer sizes.
    */
    Log("\n\n=== PHASE 2: DETAILED TESTING (dev=1) ===");
    for (USHORT func = 0; func < 0x1000; func++) {
        if (found_dev1[func]) {
            DetailIOCtl(s, MakeIOCtl(1, func), func, 1);
        }
    }
    
    Log("\n\n=== PHASE 2: DETAILED TESTING (dev=0x1200) ===");
    for (USHORT func = 0; func < 0x1000; func++) {
        if (found_dev1200[func]) {
            DetailIOCtl(s, MakeIOCtl(0x1200, func), func, 0x1200);
        }
    }
    
    /* Summary */
    Log("\n\n=== FINAL SUMMARY ===");
    LogF("Device type 1 (FILE_DEVICE_BEEP, matching 0x12127): %d codes", nfound1);
    LogF("Device type 0x1200 (FILE_DEVICE_NETWORK):           %d codes", nfound1200);
    LogF("Total recognized: %d", nfound1 + nfound1200);
    
    closesocket(s);
    WSACleanup();
    CloseHandle(logfile);
    
    printf("[+] Done. Check C:\\Users\\ross\\Desktop\\afd_brute_log.txt\n");
    return 0;
}
