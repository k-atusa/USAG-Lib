@echo off
fltmc >nul 2>&1 || (echo Admin required. & exit /b)

:: 1. Remove CLI History
del /q /f "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt" >nul 2>&1
doskey /listsize=0

:: 2. Remove Thumbnail Cache
taskkill /f /im explorer.exe >nul 2>&1
del /q /s /f "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db" >nul 2>&1
start explorer.exe

:: 3. Remove Snapshots
vssadmin delete shadows /all /quiet >nul 2>&1

:: 4. Trim/Zero-fill free disk space
cipher /w:C:

:: 5. Overwrite memory and swap
powershell -NoProfile -Command "$l=[System.Collections.Generic.List[byte[]]]::new(); try{while($true){$l.Add([byte[]]::new(104857600))}}catch{}"

echo Done.