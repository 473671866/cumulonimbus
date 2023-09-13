#pragma once

EXTERN_C_START

/// @brief 注册
/// @param key
/// @return
int RegisterKey(const char* key);

/// @brief 查询剩余时间
/// @return
char* Query();

/// @brief 判断驱动是否在线
/// @return
bool Examine();

/// @brief 加载驱动
/// @return 错误码 0为成功
int Launcher();

/// @brief 远程call
/// @param pid 进程id
/// @param shellcode
/// @param size
/// @return
bool RemoteCall(unsigned __int64 pid, void* shellcode, unsigned __int64 size);

/// @brief x64进程注入
/// @param pid 进程id
/// @param filepath 文件路径
/// @return
bool LoadLibrary_x64(unsigned __int64 pid, const char* filepath);

/// @brief x86进程注入
/// @param pid 进程id
/// @param filepath 文件路径
/// @return
bool LoadLibrary_x86(unsigned __int64 pid, const char* filepath);

/// @brief 隐藏内存
/// @param pid 进程id
/// @param address 内存地址
/// @param size 要隐藏内存的大小
/// @return
bool HideMemory(unsigned __int64 pid, void* address, unsigned __int64 size);

/// @brief 恢复被隐藏的内存
/// @param pid 进程id
/// @param address
/// @return
bool RecoverMemory(unsigned __int64 pid, void* address, unsigned __int64 size);

/// @brief 申请内存
/// @param pid 进程pid
/// @param size 申请的大小
/// @param proteced 内存属性
/// @return
void* AllocateMemory(unsigned __int64 pid, unsigned long size, unsigned __int64 protect);

/// @brief 释放内存
/// @param pid 进程pid
/// @param address 内存地址
/// @param size 内存大小
/// @return
bool FreeMemory(unsigned __int64 pid, void* address, unsigned __int64 size);

/// @brief 隐藏进程 只支持win10 win11会蓝屏
/// @param pid
/// @return
bool HideProcess(unsigned __int64 pid);

/// @brief 结束进程
/// @param pid
/// @return
bool TermiateProcess(unsigned __int64 pid);

/// @brief 获取进程模块
/// @param pid 进程id
/// @param module_name 模块名字
/// @param address 返回的模块地址
/// @param size 模块大小 可选
/// @return
bool GetApplicationModule(unsigned __int64 pid, const char* module_name, void* address, unsigned __int64* size);

/// @brief 读内存
/// @param pid 进程id
/// @param address 内存地址
/// @param buffer 返回结果
/// @param size 读取大小
/// @return
bool ReadMappingMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size);

/// @brief 读内存
/// @param pid 进程id
/// @param address 内存地址
/// @param buffer 返回结果
/// @param size 读取大小
/// @return
bool ReadPhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size);

/// @brief 写内存
/// @param pid 进程id
/// @param address 内存地址
/// @param buffer 要写的内容
/// @param size 写入的大小
/// @return
bool WritePhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size);

/// @brief 返截图
/// @param hwnd 窗口句柄
/// @return
bool AntiSrceenShot(HWND hwnd);

/// @brief 初始化窗口保护
/// @return
bool InitializeWindowProtected();

/// @brief 安装窗口保护
/// @param hwnd 窗口句柄
/// @return
bool InstallWindowProtect(HWND hwnd);

/// @brief 卸载窗口保护
/// @return
bool UnloadWindowProtected();

EXTERN_C_END
