set "d=%date:~0,10%"
date 2013/8/15

set "projectpath=%cd%"
set "path=%cd%"
cd ../
set "preProjectpath=%cd%"
cd %projectpath%

set "SignFullPath=%preProjectpath%\x64\Release\driver.sys"
set "VMPath=%preProjectpath%\x64\Release\driver.sys.vmp"
set "path=%path%;D:/vmp/;"

@ram VMProtect_Con.exe %VMPath%
D:\DSignTool\CSignTool.exe sign /r landong /f %SignFullPath% /ac
builder.exe %SignFullPath% F:\Code\Kernel\cumolonimbus\library

date %d%
pause


