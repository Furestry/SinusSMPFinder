@echo off
chcp 65001 > nul

mkdir build 2>nul || echo Папка build уже существует
cd build || exit /b 1

cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release || (
    echo Ошибка CMake!
    pause
    exit /b 1
)

cmake --build . --config Release || (
    echo Ошибка сборки!
    pause
    exit /b 1
)

echo Сборка завершена успешно. Файл создан по пути /build/SinusSMPFinder.exe
pause