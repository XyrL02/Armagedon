#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pNtCreateFile)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, LARGE_INTEGER*, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtDeviceIoControlFile)(HANDLE, HANDLE, PVOID, PVOID, IO_STATUS_BLOCK*, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

int main() {
    HMODULE ntdll = GetModuleHandleA("ntdll");
    pNtCreateFile NtCreateFile = (pNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
    pNtDeviceIoControlFile NtDeviceIoControlFile = (pNtDeviceIoControlFile)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");

    const wchar_t *paths[] = { L"\\Device\\Afd", L"\\Device\\Afd\\Endpoint" };
    const char *pnames[] = { "\\Device\\Afd", "\\Device\\Afd\\Endpoint" };
    ULONG iocals[] = { 0x1207F, 0x1207B, 0x12127, 0x120C3, 0x1204F, 0x1205B, 0x1203B, 0x1208F, 0x1212B, 0x12017 };

    for (int pi = 0; pi < 2; pi++) {
        for (int ii = 0; ii < sizeof(iocals)/sizeof(iocals[0]); ii++) {
            UNICODE_STRING us;
            RtlInitUnicodeString(&us, paths[pi]);
            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

            HANDLE h = NULL;
            IO_STATUS_BLOCK ios = {0};
            NTSTATUS st = NtCreateFile(&h, MAXIMUM_ALLOWED, &oa, &ios, NULL, 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);

            if (!NT_SUCCESS(st)) {
                printf("[%s][0x%05lx] NtCreateFile=0x%08lx\n", pnames[pi], iocals[ii], st);
                continue;
            }

            char buf[0x30] = {0};
            memset(&ios, 0, sizeof(ios));
            st = NtDeviceIoControlFile(h, NULL, NULL, NULL, &ios, iocals[ii], buf, sizeof(buf), buf, sizeof(buf));
            printf("[%s][0x%05lx] st=0x%08lx ios=0x%08lx\n", pnames[pi], iocals[ii], st, ios.Status);
            CloseHandle(h);
        }
    }
    return 0;
}
