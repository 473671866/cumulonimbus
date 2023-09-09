set "d=%date:~0,10%"
date 2013/8/15

set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd %projectpath%

set "SignFullPath=%preProjectpath%\x64\Debug\driver.sys"

@rem D:\DSignTool\CSignTool.exe sign /r landong /f %SignFullPath% /ac

builder.exe %SignFullPath% F:\Code\Kernel\cumolonimbus\application

date %d%
pause