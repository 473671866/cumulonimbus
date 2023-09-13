set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd /d %projectpath%

set "VMPath=%preProjectpath%\x64\Debug\application.exe"


set "path=%path%;D:/vmp/;"

VMProtect_Con.exe %VMPath%

pause
