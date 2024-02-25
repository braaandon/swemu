#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <MinHook.h>


typedef INT (WSAAPI* GetAddrInfoW_t)(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult);

GetAddrInfoW_t GetAddrInfoW_orig;

INT WSAAPI GetAddrInfoW_hook(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    pNodeName = L"127.0.0.1";
    return GetAddrInfoW_orig(pNodeName, pServiceName, pHints, ppResult);
}

void entry() {
    LoadLibraryA("ws2_32.dll");
    auto ws2_32 = GetModuleHandleA("ws2_32.dll");
    auto getaddrinfow_addr = GetProcAddress(ws2_32, "GetAddrInfoW");

    MH_Initialize();
    MH_CreateHook(getaddrinfow_addr, GetAddrInfoW_hook, (void**)&GetAddrInfoW_orig);
    auto status = MH_EnableHook(MH_ALL_HOOKS);

    if (status != MH_OK) {
        std::exit(-1);
    }
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        entry();
    }

    return TRUE;
}