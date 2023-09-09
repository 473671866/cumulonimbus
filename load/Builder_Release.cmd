set "path=%cd%"
set "d=%date:~0,10%"
date 2013/8/15


set "projectpath=%cd%"
cd ../
set "preProjectpath=%cd%"
cd %projectpath%
set "SignFullPath=%preProjectpath%\x64\Release\load.sys"

builder.exe %SignFullPath% F:\Code\Kernel\cumolonimbus\application
D:\DSignTool\CSignTool.exe sign /r landong /f %SignFullPath% /ac

date %d%
pause


