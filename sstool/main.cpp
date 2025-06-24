#include <cstdint>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <vector>
#include <string_view>
#include <conio.h>
#include <io.h>
#include <fcntl.h>

void CheckProcessesByName(const std::string& processName);
bool CheckSuspiciousDLLs(DWORD processID);
std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns);

std::vector<std::string_view> dllPatterns = {
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

std::vector<std::string_view> memPatterns = {
    "font.ttf",
    "Hitboxes.class",
    "canPlaceCrystalServer",
    "FontRenderer"
    "Retotem",
    "yIQDgFEROJr",
    "runecraft"
    "fastCrystal"
};

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::cout << "SinusSMPFinder | Создан luvvllx, дополнен Sevler | v1.3" << std::endl;

	// Проверяем все процессы javaw.exe на наличие подозрительных данных
    CheckProcessesByName("javaw.exe");

    std::cout << std::endl << "Нажмите любую клавишу для выхода..." << std::endl;
    _getch();

	return 0;
}

void CheckProcessesByName(const std::string& processName) {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (std::string(pe32.szExeFile) == processName) {
				std::cout << "Найден процесс " << processName << " (PID: " << pe32.th32ProcessID << ")" << std::endl;
				bool found;

				std::cout << "Поиск DLL" << std::endl;

				// Новая проверка по именам загруженных DLL
				found = CheckSuspiciousDLLs(pe32.th32ProcessID);

				std::cout << "Поиск в памяти" << std::endl;

				// Старая проверка по строкам в памяти
				HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    auto results = pattern_scan(hProcess, memPatterns);
                    std::cout << "Найдено " << std::dec << results.size() << " Читов" << std::endl;
                    CloseHandle(hProcess);

                    found = found && results.size() > 0;
                }

                std::string foundStr = "найдены читы";

                if (!found) {
                    foundStr = "не " + foundStr;
                }

                std::cout << "В процессе " << processName << " (PID: " << pe32.th32ProcessID << ") " << foundStr << std::endl;
			}
		} while (Process32Next(hSnapshot, &pe32));

		CloseHandle(hSnapshot);
	}
}

bool CheckSuspiciousDLLs(DWORD processID) {
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	char szModName[MAX_PATH];
	bool found = FALSE;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (hProcess == NULL) {
		return FALSE;
	}

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
				std::string dllName(szModName);

				for (const auto& keyword : dllPatterns) {
					if (dllName.find(keyword) != std::string::npos) {
						std::cout << "[!] Подозрительная DLL: " << dllName << std::endl;
						found = TRUE;
					}
				}
			}
		}
	}

	CloseHandle(hProcess);

	return found;
}

std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns) {
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
                        std::cout << "[*] НАЙДЕНО ЧИТОВ " << pattern << " в " << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(found) << std::endl;
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
