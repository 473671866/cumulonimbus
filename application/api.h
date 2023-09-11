#pragma once
#include <iostream>
#include <windows.h>

/// @brief �ж������Ƿ�����
/// @return
boolean Examine();

/// @brief ��������
/// @return
boolean Launcher();

/// @brief Զ��call
/// @param pid ����id
/// @param shellcode
/// @param size
/// @return
boolean RemoteCall(uint64_t pid, void* shellcode, size_t size);

/// @brief x64����ע��
/// @param pid ����id
/// @param filepath �ļ�·��
/// @return
boolean LoadLibrary_x64(uint64_t pid, const char* filepath);

/// @brief x86����ע��
/// @param pid ����id
/// @param filepath �ļ�·��
/// @return
boolean LoadLibrary_x86(uint64_t pid, const char* filepath);

/// @brief �����ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param size Ҫ�����ڴ�Ĵ�С
/// @return
boolean HideMemory(uint64_t pid, uint64_t address, size_t size);

/// @brief �ָ������ص��ڴ�
/// @param address
/// @return
boolean RecoverMemory(uint64_t address);

/// @brief �����ڴ�
/// @param pid ����pid
/// @param size ����Ĵ�С
/// @param proteced �ڴ�����
/// @return
void* AllocateMemory(uint64_t pid, size_t size, uint32_t proteced);

/// @brief �ͷ��ڴ�
/// @param pid ����pid
/// @param address �ڴ��ַ
/// @param size �ڴ��С
/// @return
boolean FreeMemory(uint64_t pid, void* address, size_t size);

/// @brief ���ؽ��� ֻ֧��win10 win11������
/// @param pid
/// @return
boolean HideProcess(uint64_t pid);

/// @brief ��������
/// @param pid
/// @return
boolean TermiateProcess(uint64_t pid);

/// @brief ��ȡ����ģ��
/// @param pid ����id
/// @param module_name ģ������
/// @param address ���ص�ģ���ַ
/// @param size ģ���С ��ѡ
/// @return
boolean GetApplicationModule(uint64_t pid, const char* module_name, void* address, size_t* size);

/// @brief ���ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer ���ؽ��
/// @param size ��ȡ��С
/// @return
boolean ReadMappingMemory(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief ���ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer ���ؽ��
/// @param size ��ȡ��С
/// @return
boolean ReadPhysicalMemory(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief д�ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer Ҫд������
/// @param size д��Ĵ�С
/// @return
boolean WritePhysicalMemory(uint64_t pid, uint64_t address, void* buffer, size_t size);

/// @brief ����ͼ
/// @param hwnd ���ھ��
/// @return
boolean AntiSrceenShot(HWND hwnd);
