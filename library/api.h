#pragma once

EXTERN_C_START

/// @brief ע��
/// @param key
/// @return
int RegisterKey(const char* key);

/// @brief ��ѯʣ��ʱ��
/// @return
char* Query();

/// @brief �ж������Ƿ�����
/// @return
bool Examine();

/// @brief ��������
/// @return ������ 0Ϊ�ɹ�
int Launcher();

/// @brief Զ��call
/// @param pid ����id
/// @param shellcode
/// @param size
/// @return
bool RemoteCall(unsigned __int64 pid, void* shellcode, unsigned __int64 size);

/// @brief x64����ע��
/// @param pid ����id
/// @param filepath �ļ�·��
/// @return
bool LoadLibrary_x64(unsigned __int64 pid, const char* filepath);

/// @brief x86����ע��
/// @param pid ����id
/// @param filepath �ļ�·��
/// @return
bool LoadLibrary_x86(unsigned __int64 pid, const char* filepath);

/// @brief �����ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param size Ҫ�����ڴ�Ĵ�С
/// @return
bool HideMemory(unsigned __int64 pid, void* address, unsigned __int64 size);

/// @brief �ָ������ص��ڴ�
/// @param pid ����id
/// @param address
/// @return
bool RecoverMemory(unsigned __int64 pid, void* address, unsigned __int64 size);

/// @brief �����ڴ�
/// @param pid ����pid
/// @param size ����Ĵ�С
/// @param proteced �ڴ�����
/// @return
void* AllocateMemory(unsigned __int64 pid, unsigned long size, unsigned __int64 protect);

/// @brief �ͷ��ڴ�
/// @param pid ����pid
/// @param address �ڴ��ַ
/// @param size �ڴ��С
/// @return
bool FreeMemory(unsigned __int64 pid, void* address, unsigned __int64 size);

/// @brief ���ؽ��� ֻ֧��win10 win11������
/// @param pid
/// @return
bool HideProcess(unsigned __int64 pid);

/// @brief ��������
/// @param pid
/// @return
bool TermiateProcess(unsigned __int64 pid);

/// @brief ��ȡ����ģ��
/// @param pid ����id
/// @param module_name ģ������
/// @param address ���ص�ģ���ַ
/// @param size ģ���С ��ѡ
/// @return
bool GetApplicationModule(unsigned __int64 pid, const char* module_name, void* address, unsigned __int64* size);

/// @brief ���ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer ���ؽ��
/// @param size ��ȡ��С
/// @return
bool ReadMappingMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size);

/// @brief ���ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer ���ؽ��
/// @param size ��ȡ��С
/// @return
bool ReadPhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size);

/// @brief д�ڴ�
/// @param pid ����id
/// @param address �ڴ��ַ
/// @param buffer Ҫд������
/// @param size д��Ĵ�С
/// @return
bool WritePhysicalMemory(unsigned __int64 pid, void* address, void* buffer, unsigned __int64 size);

/// @brief ����ͼ
/// @param hwnd ���ھ��
/// @return
bool AntiSrceenShot(HWND hwnd);

/// @brief ��ʼ�����ڱ���
/// @return
bool InitializeWindowProtected();

/// @brief ��װ���ڱ���
/// @param hwnd ���ھ��
/// @return
bool InstallWindowProtect(HWND hwnd);

/// @brief ж�ش��ڱ���
/// @return
bool UnloadWindowProtected();

EXTERN_C_END
