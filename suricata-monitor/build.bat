@echo off
echo [*] Останавливаю старый процесс...
taskkill /F /IM SuricataMonitor.exe 2>nul

echo [*] Удаляю старые сборки...
rmdir /S /Q dist 2>nul
rmdir /S /Q build 2>nul
del /Q SuricataMonitor.spec 2>nul

echo [*] Собираю EXE...
pyinstaller --onefile --console --uac-admin --name "MelnickSuricataMonitor" --icon "src\icon.ico" src\test.py

echo.
echo [+] Готово: dist\MelnickSuricataMonitor.exe
pause