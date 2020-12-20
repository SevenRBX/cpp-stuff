#include <Windows.h>
#include <string>
#include <iostream>

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

/*Print exploit that doesnt suck ass
made by Phoenixx*/

uintptr_t aslr(uintptr_t addr) { return (addr - 0x400000 + reinterpret_cast<uintptr_t>(GetModuleHandleA(0))); }

DWORD PrintAslr = 0x0064FB50;

typedef int(__cdecl* r_print_typedef)(int a1, const char* a2);
r_print_typedef  r_print = (r_print_typedef)(aslr(PrintAslr));

/*Console Bypass*/
void BypassConsole()
{
	DWORD Rblx;
	VirtualProtect((PVOID)&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &Rblx);
	*(BYTE*)(&FreeConsole) = 0xC3;
}

void start() {
	/*DAC Bypass by Static*/
    DWORD pid;
    GetWindowThreadProcessId(FindWindowA(NULL, "Roblox"), &pid);

    if (!pid) return;

    HANDLE roblox_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!roblox_handle) return;

    const auto addr_ldrloaddll = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll"));
    const auto addr_bypass = reinterpret_cast<void*>(addr_ldrloaddll - 5);


    DWORD old, n_bytes_write;
    VirtualProtectEx(roblox_handle, addr_bypass, 5, PAGE_EXECUTE_READWRITE, &old);
    uint8_t payload[] = { 0x55, 0x8B, 0xEC, 0xEB, 0x05 };
    WriteProcessMemory(roblox_handle, addr_bypass, &payload, 5, &n_bytes_write);
    VirtualProtectEx(roblox_handle, addr_bypass, 5, old, &old);

    const auto addr_pointer = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(GetModuleHandleA("KERNELBASE.dll")) + 0x1CA6AC); // see the LdrLoadDll call, inside LoadLibraryExW

    VirtualProtectEx(roblox_handle, addr_pointer, 4, PAGE_READWRITE, &old);
    WriteProcessMemory(roblox_handle, addr_pointer, &addr_bypass, 4, &n_bytes_write);
    VirtualProtectEx(roblox_handle, addr_pointer, 4, PAGE_READONLY, &old);

	/*main*/
	BypassConsole();
	AllocConsole();
	SetConsoleTitleA("Undetected Print");
	freopen("CONOUT$", "w", stdout);
	freopen("CONIN$", "r", stdin);
	HWND ConHan = GetConsoleWindow();
	::SetWindowPos(ConHan, NULL, 0, 0, 0, 0, SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
	::ShowWindow(ConHan, SW_NORMAL);

	printf("loading adresses...\r\n");

	printf("ready to print.\n");

    do {
        std::string input = "";
        std::getline(std::cin, input);
        r_print(0, input.c_str());
        printf("successfully done operation.\n");
    } while (true);
}

unsigned int ProtectSections(HMODULE Module)
{
    MODULEINFO ModuleInfo;
    GetModuleInformation(GetCurrentProcess(), Module, &ModuleInfo, sizeof(ModuleInfo));
    uintptr_t Address = reinterpret_cast<uintptr_t>(Module);
    uintptr_t TermAddress = Address + ModuleInfo.SizeOfImage;
    MEMORY_BASIC_INFORMATION MemoryInfo;


    while (Address < TermAddress) {
        VirtualQuery(reinterpret_cast<void*>(Address), &MemoryInfo, sizeof(MemoryInfo));
        if (MemoryInfo.State == MEM_COMMIT && (MemoryInfo.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            DWORD OldProtection;
            VirtualProtect(reinterpret_cast<void*>(Address), MemoryInfo.RegionSize, PAGE_EXECUTE_READ, &OldProtection);
        }
        Address = reinterpret_cast<uintptr_t>(MemoryInfo.BaseAddress) + MemoryInfo.RegionSize;
    }

    VirtualQuery(reinterpret_cast<void*>(MemoryInfo.AllocationBase), &MemoryInfo, sizeof(MemoryInfo));
    if (MemoryInfo.State != MEM_COMMIT || !(MemoryInfo.Protect & PAGE_EXECUTE_READ))
        return 0x400;
    return MemoryInfo.RegionSize - 0x400;
}

__forceinline void UnlinkModule(HINSTANCE Module
) {
	unsigned long PEB_DATA = 0;
	_asm {
		pushad;
		pushfd;
		mov eax, fs: [30h]
			mov eax, [eax + 0Ch]
			mov PEB_DATA, eax

			InLoadOrderModuleList :
		mov esi, [eax + 0Ch]
			mov edx, [eax + 10h]

			LoopInLoadOrderModuleList :
			lodsd
			mov esi, eax
			mov ecx, [eax + 18h]
			cmp ecx, Module
			jne SkipA
			mov ebx, [eax]
			mov ecx, [eax + 4]
			mov[ecx], ebx
			mov[ebx + 4], ecx
			jmp InMemoryOrderModuleList

			SkipA :
		cmp edx, esi
			jne LoopInLoadOrderModuleList

			InMemoryOrderModuleList :
		mov eax, PEB_DATA
			mov esi, [eax + 14h]
			mov edx, [eax + 18h]

			LoopInMemoryOrderModuleList :
			lodsd
			mov esi, eax
			mov ecx, [eax + 10h]
			cmp ecx, Module
			jne SkipB
			mov ebx, [eax]
			mov ecx, [eax + 4]
			mov[ecx], ebx
			mov[ebx + 4], ecx
			jmp InInitializationOrderModuleList

			SkipB :
		cmp edx, esi
			jne LoopInMemoryOrderModuleList

			InInitializationOrderModuleList :
		mov eax, PEB_DATA
			mov esi, [eax + 1Ch]
			mov edx, [eax + 20h]

			LoopInInitializationOrderModuleList :
			lodsd
			mov esi, eax
			mov ecx, [eax + 08h]
			cmp ecx, Module
			jne SkipC
			mov ebx, [eax]
			mov ecx, [eax + 4]
			mov[ecx], ebx
			mov[ebx + 4], ecx
			jmp Finished

			SkipC :
		cmp edx, esi
			jne LoopInInitializationOrderModuleList

			Finished :
		popfd;
		popad;
	}
}

BOOL APIENTRY DllMain(HMODULE Module, DWORD Reason, void* Reserved)
{
	DisableThreadLibraryCalls(Module);
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
	{
		UnlinkModule(Module);
		DWORD OldProtection;
		VirtualProtect(Module, 4096, PAGE_READWRITE, &OldProtection);
		ZeroMemory(Module, 4096);
		ProtectSections(Module);
		HANDLE hThread = NULL;
		HANDLE hDllMainThread = GetCurrentThread();
		if (Reserved == NULL) {
			if (!(hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)start, NULL, NULL, NULL)))
			{
				CloseHandle(hDllMainThread);
				return FALSE;
			}
			CloseHandle(hThread);
		}
		break;
	}
	case DLL_PROCESS_DETACH:
	{
	}
	}
	return TRUE;
}