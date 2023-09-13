set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd /d %projectpath%

set "VMPath=%preProjectpath%\x64\Release\library.dll.vmp"


set "path=%path%;D:/vmp/;"

VMProtect_Con.exe %VMPath%

pause
