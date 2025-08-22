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
#include <tuple>
#include <future>
#include <mutex>
#include "no_strings.hpp"

void CheckProcessesByName(const std::string& processName);
std::vector<void*> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns);

constexpr auto encryptedPatterns = std::tuple{
    #include "patterns.inc"
};

const std::vector<std::string_view> memPatterns = []() {
    std::vector<std::string_view> result;
    std::apply([&](const auto&... es) {
        (result.push_back(es.decrypt()), ...);
    }, encryptedPatterns);
    return result;
}();

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "SinusSMPFinder | Создан luvvllx, дополнен Sevler | v1.6\n";

    auto start_time = std::chrono::high_resolution_clock::now();

    if (memPatterns.size() > 0) {
        CheckProcessesByName("javaw.exe");
    } else {
        std::cout << "Список шаблонов строк пустой\n";
    }

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

bool case_insensitive_match(std::string_view haystack, std::string_view needle, size_t start_pos) {
    if (start_pos + needle.size() > haystack.size()) {
        return false;
    }

    for (size_t i = 0; i < needle.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(haystack[start_pos + i])) != needle[i]) {
            return false;
        }
    }

    return true;
}

std::mutex console_mutex;

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

    SIZE_T max_pattern_length = 0;
    for (const auto& pattern : patterns) {
        max_pattern_length = std::max(max_pattern_length, pattern.size());
    }

    uint8_t* address = static_cast<uint8_t*>(sys_info.lpMinimumApplicationAddress);
    const SIZE_T chunk_size = 16 * 1024 * 1024;
    std::vector<uint8_t> buffer(chunk_size);

    while (address < sys_info.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION memInfo;

        if (!VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
            break;
        }

        scanned_regions++;
        float progress = static_cast<float>(scanned_regions) / total_regions;
        int barWidth = 50;

        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "\r[";

            int pos = static_cast<int>(barWidth * progress);

            for (int i = 0; i < barWidth; ++i) {
                if (i < pos) {
                    std::cout << "=";
                } else if (i == pos) {
                    std::cout << ">";
                } else {
                    std::cout << " ";
                }
            }

            std::cout << "] " << std::setw(3) << static_cast<int>(progress * 100.0) << "%";
            std::cout << " | Регион " << scanned_regions << "/" << total_regions;
            std::cout.flush();
        }

        if (memInfo.State == MEM_COMMIT && (memInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            SIZE_T bytes_remaining = memInfo.RegionSize;
            uint8_t* region_address = static_cast<uint8_t*>(memInfo.BaseAddress);
            std::vector<std::future<std::vector<void*>>> futures;

            while (bytes_remaining > 0) {
                SIZE_T bytes_to_read = std::min(chunk_size, bytes_remaining);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, region_address, buffer.data(), bytes_to_read, &bytesRead)) {
                    total_bytes_scanned += bytesRead;
                    std::string_view view(reinterpret_cast<char*>(buffer.data()), bytesRead);

                    futures.push_back(std::async(std::launch::async, [view, &lower_patterns, &patterns, region_address]() {
                        std::vector<void*> local_results;

                        for (size_t i = 0; i < patterns.size(); ++i) {
                            size_t pos = 0;

                            while (pos + patterns[i].size() <= view.size()) {
                                if (case_insensitive_match(view, lower_patterns[i], pos)) {
                                    void* found = region_address + pos;
                                    {
                                        std::lock_guard<std::mutex> lock(console_mutex);
                                        std::cout << "\n[*] Найдено: " << patterns[i] << " по адресу 0x"
                                                  << std::hex << reinterpret_cast<uintptr_t>(found) << std::dec;
                                        std::cout.flush();
                                    }

                                    local_results.push_back(found);
                                    pos += patterns[i].size();
                                } else {
                                    ++pos;
                                }
                            }
                        }

                        return local_results;
                    }));
                }

                region_address += bytesRead - max_pattern_length;
                bytes_remaining -= (bytesRead > max_pattern_length ? bytesRead - max_pattern_length : bytesRead);
            }

            for (auto& future : futures) {
                auto local_results = future.get();
                results.insert(results.end(), local_results.begin(), local_results.end());
            }
        }

        address = static_cast<uint8_t*>(memInfo.BaseAddress) + memInfo.RegionSize;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    {
        std::lock_guard<std::mutex> lock(console_mutex);
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
    }

    return results;
}