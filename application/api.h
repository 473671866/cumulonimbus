#pragma once
#include <iostream>
#include <windows.h>
EXTERN_C_START

/// @brief 注册
/// @param key
/// @return
typedef int (*RegisterKeyProc)(const char* key);

/// @brief 查询剩余时间
/// @return
typedef char* (*QueryProc)();

/// @brief 判断驱动是否在线
/// @return
typedef boolean(*ExamineProc)();

/// @brief 加载驱动
/// @return 错误码 0为成功
typedef int (*LauncherProc)();

/// @brief 远程call
/// @param pid 进程id
/// @param shellcode
/// @param size
/// @return
typedef boolean(*RemoteCallProc)(uint64_t pid, void* shellcode, size_t size);

/// @brief x64进程注入
/// @param pid 进程id
/// @param filepath 文件路径
/// @return
typedef boolean(*LoadLibrary_x64Proc)(uint64_t pid, const char* filepath);

/// @brief x86进程注入
/// @param pid 进程id
/// @param filepath 文件路径
/// @return
typedef boolean(*LoadLibrary_x86Proc)(uint64_t pid, const char* filepath);

/// @brief 隐藏内存
/// @param pid 进程id
/// @param address 内存地址
/// @param size 要隐藏内存的大小
/// @return
typedef boolean(*HideMemoryProc)(uint64_t pid, void* address, size_t size);

/// @brief 恢复被隐藏的内存
/// @param address
/// @return
typedef boolean(*RecoverMemoryProc)(uint64_t pid, void* address, size_t size);

/// @brief 申请内存
/// @param pid 进程pid
/// @param size 申请的大小
/// @param proteced 内存属性
/// @return
typedef void* (*AllocateMemoryProc)(uint64_t pid, size_t size, uint32_t proteced);

/// @brief 释放内存
/// @param pid 进程pid
/// @param address 内存地址
/// @param size 内存大小
/// @return
typedef boolean(*FreeMemoryProc)(uint64_t pid, void* address, size_t size);

/// @brief 隐藏进程 只支持win10 win11会蓝屏
/// @param pid
/// @return
typedef boolean(*HideProcessProc)(uint64_t pid);

/// @brief 结束进程
/// @param pid
/// @return
typedef boolean(*TermiateProcessProc)(uint64_t pid);

/// @brief 获取进程模块
/// @param pid 进程id
/// @param module_name 模块名字
/// @param address 返回的模块地址
/// @param size 模块大小 可选
/// @return
typedef boolean(*GetApplicationModuleProc)(uint64_t pid, const char* module_name, void* address, size_t* size);

/// @brief 读内存
/// @param pid 进程id
/// @param address 内存地址
/// @param buffer 返回结果
/// @param size 读取大小
/// @return
typedef boolean(*ReadMappingMemoryProc)(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief 读内存
/// @param pid 进程id
/// @param address 内存地址
/// @param buffer 返回结果
/// @param size 读取大小
/// @return
typedef boolean(*ReadPhysicalMemoryProc)(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief 写内存
/// @param pid 进程id
/// @param address 内存地址
/// @param buffer 要写的内容
/// @param size 写入的大小
/// @return
typedef boolean(*WritePhysicalMemoryProc)(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief 返截图
/// @param hwnd 窗口句柄
/// @return
typedef boolean(*AntiSrceenShotProc)(HWND hwnd);

/// @brief 初始化窗口保护
/// @return
typedef boolean(*InitializeWindowProtectedProc)();

/// @brief 安装窗口保护
/// @param hwnd 窗口句柄
/// @return
typedef boolean(*InstallWindowProtectProc)(HWND hwnd);

/// @brief 卸载窗口保护
/// @return
typedef boolean(*UnloadWindowProtectedProc)();

EXTERN_C_END
