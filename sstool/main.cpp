#include <cstdint>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <vector>
#include <string_view>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <iomanip>

void CheckProcessesByName(const std::string& processName);
std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns);

std::vector<std::string_view> memPatterns = {
    "font.ttf",
    "canPlaceCrystalServer",
    "Freecam"
    "Retotem",
    "yIQDgFEROJr",
    "AutoTotem"
    "ItemScroller"
    "runecraft"
    "fastCrystal"
};

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "SinusSMPFinder | Создан luvvllx, дополнен Sevler | v1.4.2\n";

    auto start_time = std::chrono::high_resolution_clock::now();

    CheckProcessesByName("javaw.exe");

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::cout << "\nОбщее Затраченное время: " << duration.count() << " мс\n";
    std::cout << "\nНажмите Enter для выхода...";

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    return 0;
}

void CheckProcessesByName(const std::string& processName) {
    PROCESSENTRY32 pe32{ sizeof(PROCESSENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (std::string(pe32.szExeFile) == processName) {
                std::cout << "Найден процесс " << processName << " (PID: " << pe32.th32ProcessID << ")\n";

                HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);

                if (hProcess) {
                    auto results = pattern_scan(hProcess, memPatterns);
                    std::cout << "Найдено " << results.size() << " читов\n";

                    CloseHandle(hProcess);

                    std::cout << "В процессе " << processName << " (PID: " << pe32.th32ProcessID << ") "
                              << (results.empty() ? "не найдены читы" : "найдены читы") << "\n";
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}

std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns) {
    auto start_time = std::chrono::high_resolution_clock::now();

    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    std::vector<void*> results;
    std::vector<std::string> lower_patterns;
    lower_patterns.reserve(patterns.size());

    for (const auto& pattern : patterns) {
        std::string lower(pattern);
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
        lower_patterns.emplace_back(std::move(lower));
    }

    size_t total_bytes_scanned = 0;
    size_t total_regions = 0;
    size_t scanned_regions = 0;
    uint8_t* count_address = static_cast<uint8_t*>(sys_info.lpMinimumApplicationAddress);

    while (count_address < sys_info.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION memInfo;

        if (!VirtualQueryEx(hProcess, count_address, &memInfo, sizeof(memInfo))) {
            break;
        }

        total_regions++;
        count_address = static_cast<uint8_t*>(memInfo.BaseAddress) + memInfo.RegionSize;
    }

    uint8_t* address = static_cast<uint8_t*>(sys_info.lpMinimumApplicationAddress);
    MEMORY_BASIC_INFORMATION memInfo;

    while (address < sys_info.lpMaximumApplicationAddress) {
        if (!VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
            break;
        }

        scanned_regions++;
        float progress = static_cast<float>(scanned_regions) / total_regions;
        int barWidth = 50;

        std::cout << "\r[";
        int pos = static_cast<int>(barWidth * progress);

        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) {
                std::cout << "=";
            } else if (i == pos) {
                std::cout << ">";
            }
            else {
                std::cout << " ";
            }
        }

        std::cout << "] " << std::setw(3) << static_cast<int>(progress * 100.0) << "%";
        std::cout << " | Регион " << scanned_regions << "/" << total_regions;
        std::cout.flush();

        if (memInfo.State == MEM_COMMIT &&
            (memInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {

            std::vector<uint8_t> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                total_bytes_scanned += bytesRead;

                std::string_view view(reinterpret_cast<char*>(buffer.data()), bytesRead);
                std::string lower_view;
                lower_view.reserve(view.size());

                for (char c : view) {
                    lower_view.push_back(std::tolower(static_cast<unsigned char>(c)));
                }

                for (size_t i = 0; i < patterns.size(); ++i) {
                    size_t pos = 0;
                    while ((pos = lower_view.find(lower_patterns[i], pos)) != std::string::npos) {
                        void* found = static_cast<uint8_t*>(memInfo.BaseAddress) + pos;
                        std::cout << "\n[*] Найдено: " << patterns[i] << " по адресу 0x"
                                 << std::hex << reinterpret_cast<uintptr_t>(found) << std::dec;
                        results.push_back(found);
                        pos += patterns[i].size();
                    }
                }
            }
        }

        address = static_cast<uint8_t*>(memInfo.BaseAddress) + memInfo.RegionSize;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::cout << "\n=== Статистика поиска ===";
    std::cout << "\nПроверено регионов памяти: " << total_regions;
    std::cout << "\nПросканировано байт: " << total_bytes_scanned / (1024 * 1024) << " MB";
    std::cout << "\nНайдено совпадений: " << results.size();
    std::cout << "\nЗатраченное время: " << duration.count() << " мс";
    std::cout << "\nСкорость сканирования: "
              << std::fixed << std::setprecision(2)
              << (total_bytes_scanned / (1024.0 * 1024.0)) / (duration.count() / 1000.0)
              << " МБ/с";
    std::cout << "\n========================\n";

    return results;
}
