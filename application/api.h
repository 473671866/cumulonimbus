#pragma once
#include <iostream>
#include <windows.h>
EXTERN_C_START

/// @brief ע��
/// @param key
/// @return
typedef int (*RegisterKeyProc)(const char* key);

/// @brief ��ѯʣ��ʱ��
/// @return
typedef char* (*QueryProc)();

/// @brief �ж������Ƿ�����
/// @return
typedef boolean(*ExamineProc)();

/// @brief ��������
/// @return ������ 0Ϊ�ɹ�
typedef int (*LauncherProc)();

/// @brief Զ��call
/// @param pid ����id
/// @param shellcode
/// @param size
/// @return
typedef boolean(*RemoteCallProc)(uint64_t pid, void* shellcode, size_t size);

/// @brief x64����ע��
/// @param pid ����id
/// @param filepath �ļ�·��
/// @return
typedef boolean(*LoadLibrary_x64Proc)(uint64_t pid, const char* filepath);

/// @brief x86����ע��
/// @param pid ����id
/// @param filepath �ļ�·��
/// @return
typedef boolean(*LoadLibrary_x86Proc)(uint64_t pid, const char* filepath);

/// @brief �����ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param size Ҫ�����ڴ�Ĵ�С
/// @return
typedef boolean(*HideMemoryProc)(uint64_t pid, void* address, size_t size);

/// @brief �ָ������ص��ڴ�
/// @param address
/// @return
typedef boolean(*RecoverMemoryProc)(uint64_t pid, void* address, size_t size);

/// @brief �����ڴ�
/// @param pid ����pid
/// @param size ����Ĵ�С
/// @param proteced �ڴ�����
/// @return
typedef void* (*AllocateMemoryProc)(uint64_t pid, size_t size, uint32_t proteced);

/// @brief �ͷ��ڴ�
/// @param pid ����pid
/// @param address �ڴ��ַ
/// @param size �ڴ��С
/// @return
typedef boolean(*FreeMemoryProc)(uint64_t pid, void* address, size_t size);

/// @brief ���ؽ��� ֻ֧��win10 win11������
/// @param pid
/// @return
typedef boolean(*HideProcessProc)(uint64_t pid);

/// @brief ��������
/// @param pid
/// @return
typedef boolean(*TermiateProcessProc)(uint64_t pid);

/// @brief ��ȡ����ģ��
/// @param pid ����id
/// @param module_name ģ������
/// @param address ���ص�ģ���ַ
/// @param size ģ���С ��ѡ
/// @return
typedef boolean(*GetApplicationModuleProc)(uint64_t pid, const char* module_name, void* address, size_t* size);

/// @brief ���ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer ���ؽ��
/// @param size ��ȡ��С
/// @return
typedef boolean(*ReadMappingMemoryProc)(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief ���ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer ���ؽ��
/// @param size ��ȡ��С
/// @return
typedef boolean(*ReadPhysicalMemoryProc)(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief д�ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer Ҫд������
/// @param size д��Ĵ�С
/// @return
typedef boolean(*WritePhysicalMemoryProc)(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief ����ͼ
/// @param hwnd ���ھ��
/// @return
typedef boolean(*AntiSrceenShotProc)(HWND hwnd);

/// @brief ��ʼ�����ڱ���
/// @return
typedef boolean(*InitializeWindowProtectedProc)();

/// @brief ��װ���ڱ���
/// @param hwnd ���ھ��
/// @return
typedef boolean(*InstallWindowProtectProc)(HWND hwnd);

/// @brief ж�ش��ڱ���
/// @return
typedef boolean(*UnloadWindowProtectedProc)();

EXTERN_C_END
