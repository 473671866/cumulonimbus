set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd /d %projectpath%

set "VMPath=%preProjectpath%\Release\application.dll"


set "path=%path%;D:/vmp/;"

VMProtect_Con.exe %VMPath%

pause
