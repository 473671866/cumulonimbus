set "path=%cd%"
set "d=%date:~0,10%"
date 2013/8/15


set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd %projectpath%
set "SignFullPath=%preProjectpath%\x64\Release\load.sys"

D:\DSignTool\CSignTool.exe sign /r landong /f %SignFullPath% /ac
builder.exe %SignFullPath% F:\Code\Kernel\cumolonimbus\application

date %d%
pause


