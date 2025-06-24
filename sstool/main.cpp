#include <cstdint>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <vector>
#include <string_view>
#include <conio.h>

std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns);

std::vector<std::string_view> novaPatterns = {
    "font.ttf",
    "Hitboxes.class",
    "canPlaceCrystalServer",
    "FontRenderer"
    "Retotem",
    "yIQDgFEROJr",
    "runecraft"
    "fastCrystal",
	"cheat",
	"hack",
	"inject",
	"xray",
	"wurst",
	"vape"
};

int main() {
    std::cout << " SinusSMPFinder | MADE BY luvvllx & Sevler v1.3\n";

	// Проверяем все процессы javaw.exe на наличие подозрительных данных
    FindProcessByName("javaw.exe");

    std::cout << "\nНажмите любую клавишу для выхода...\n";
    _getch();

	return 0;
}

void FindProcessByName(const std::string& processName) {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (std::string(pe32.szExeFile) == processName) {
				std::cout << "Найден процесс " << processName << " (PID: " << pe32.th32ProcessID << ")" << std::endl;

				// Новая проверка по именам загруженных DLL
				CheckSuspiciousDLLs(pe32.th32ProcessId);

				// Старая проверка по строкам в памяти
				auto results = pattern_scan(pe32.th32ProcessId, novaPatterns);

        		std::cout << "Найдено " << std::dec << results.size() << " Читов\n";
			}
		} while (Process32Next(hSnapshot, &pe32));

		CloseHandle(hSnapshot);
	}
}

void CheckSuspiciousDLLs(DWORD processID) {
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	char szModName[MAX_PATH];

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (hProcess == NULL) {
		return;
	}

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
				std::string dllName(szModName);

				for (const auto& keyword : novaPatterns) {
					if (dllName.find(keyword) != std::string::npos) {
						std::cout << "[!] Подозрительная DLL: " << dllName << std::endl;
					}
				}
			}
		}
	}

	CloseHandle(hProcess);
}

std::vector<void*> pattern_scan(DWORD processId, const std::vector<std::string_view>& patterns) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    std::vector<void*> results;
    MEMORY_BASIC_INFORMATION memInfo;
    uint8_t* address = static_cast<uint8_t*>(sys_info.lpMinimumApplicationAddress);

    while (address < sys_info.lpMaximumApplicationAddress && VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
        if (memInfo.State == MEM_COMMIT && (memInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            memInfo.Type == MEM_PRIVATE) {

            std::vector<uint8_t> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                std::string_view view(reinterpret_cast<char*>(buffer.data()), bytesRead);

                for (const auto& pattern : patterns) {
                    size_t pos = 0;
                    while ((pos = view.find(pattern, pos)) != std::string_view::npos) {
                        void* found = static_cast<uint8_t*>(memInfo.BaseAddress) + pos;
                        std::cout << "[*] FOUND HACKS " << pattern << " at " << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(found) << "\n";
                        results.push_back(found);
                        ++pos;
                    }
                }
            }
        }
		
        address = static_cast<uint8_t*>(memInfo.BaseAddress) + memInfo.RegionSize;
    }
	
    return results;
}
