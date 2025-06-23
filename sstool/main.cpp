#include <cstdint>
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <string_view>

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

};

std::vector<std::string_view> universalPatterns = {

};

std::vector<std::string> clientList = {
    "Run",
    "DONT WORK RN"
};

int main() {
    std::cout << " SinusSMP Finder | MADE BY luvvllx v1.2\n";

    DWORD pid;
    std::cout << "Minecraft PID:";
    std::cin >> pid;

    auto handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

    if (!handle) {
        std::cout << "\n Invalid | (PID)  \n";
        main();
    } else {
        std::cout << "Select mode: \n";

        for (int i = 0; i < clientList.size(); i++) {
            std::cout << (i + 1) << ". " << clientList.at(i) << "\n";
        }

        int option;
        std::cin >> option;
        std::vector<std::string_view> scannable;
        switch (option) {
            case 1: {
                    scannable = novaPatterns;
                    break;
            }
            case 2: {
                    scannable = universalPatterns;
                    break;
            }
        }

        auto results = pattern_scan(handle, scannable);

        std::cout << "FOUND " << std::dec << results.size() << " HACKS \n";
    }

    std::cout << "preess any key\n";
    std::cin.ignore();
    std::cin.get();

	return 0;
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
