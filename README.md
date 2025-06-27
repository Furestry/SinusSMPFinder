# SS-Инструмент
Screenshare инструмент для Minecraft

Простой сканер строк по шаблону для... любой программы, но сделан для Minecraft.

# Как использовать?
- Открыть .exe файл
- Просто ждать...

# Как Я могу добавить свои строки?
- Для начала изучить C++. Добавление строк в данный инструмент очень простое.
- Использовать C++20 с Мульти-Байт Списком Символов

# Внесение вклада
- Вы должны проверить, существует ли строка в оригинальной игре.
- Вы должны проверить код и отладить его на наличие ошибок, в противном случае ваш запрос на включение не будет принят.

# Сборка с помощью mingw64:
- Установить [mingw64](https://www.mingw-w64.org/downloads/)
- `g++ -std=c++20 -static -static-libgcc -static-libstdc++ resources.o -o SinusSMPFinder.exe main.cpp -lpsapi -s -Wl,--gc-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -Oz -Wl,-eprogram -nostartfiles -Wl,--file-alignment=0x8,--section-alignment=0x8`
