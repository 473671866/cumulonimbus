#pragma once
#include "../standard/base.h"

namespace utils {
	class search {
	private:
		/// @brief ���ַ�ת��Ϊ16����
		/// @param ch
		/// @return
		unsigned char atoh(unsigned char* ch) {
			unsigned char temps[2] = { 0 };
			for (int i = 0; i < 2; i++) {
				if (ch[i] >= '0' && ch[i] <= '9') {
					temps[i] = (ch[i] - '0');
				}
				else if (ch[i] >= 'A' && ch[i] <= 'F') {
					temps[i] = (ch[i] - 'A') + 0xA;
				}
				else if (ch[i] >= 'a' && ch[i] <= 'f') {
					temps[i] = (ch[i] - 'a') + 0xA;
				}
			}
			return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
		}

		/**
		* @brief ���ַ���ת��Ϊ�ֽ�
		* @param HardCode
		* @param CharCode
		* @return �����볤��
		*/
		int initialize(unsigned char* hex, unsigned char* ch) {
			int i = 0;
			for (i = 0; *ch != '\0'; i++) {
				if (*ch == '*' || *ch == '?') {
					hex[i] = *ch;
					ch++;
					continue;
				}

				hex[i] = atoh(ch);
				ch += 2;
			}
			return i;
		}

		unsigned __int64 compare(unsigned char* hex, unsigned __int64 start, unsigned __int64 end, unsigned __int64 length) {
			unsigned __int64 result = 0;
			unsigned __int64 j = 0;
			unsigned __int8* temp = nullptr;

			for (unsigned __int64 address = start; address <= end; address++) {
				//�����ַ���ܷ��ʣ���������һ������ҳ
				if (!MmIsAddressValid((void*)address)) {
					address = (address & (~0xFFF)) + PAGE_SIZE - 1;
					continue;
				}

				temp = (unsigned char*)address;

				for (j = 0; j < length; j++) {
					if (!MmIsAddressValid(temp + j)) {
						break;
					}

					if (hex[j] == '*' || hex[j] == '?') {
						continue;
					}

					if (temp[j] != hex[j]) {
						break;
					}

					if (j == length) {
						result = address;
						break;
					}
				}
				return result;
			}
		}

	public:
		/// @brief ��������
		/// @param address ��ʼ��ַ
		/// @param size ��С
		/// @param signature ǩ��
		/// @return
		template<typename _VA, typename _Res>
		_Res pattern(_VA address, unsigned __int64 size, const char* signature)
		{
			//��ʼ��
			unsigned char hex[0x200]{ NULL };
			int length = this->initialize(hex, (unsigned char*)signature);
			return (_Res)this->compare(hex, (unsigned __int64)address, (unsigned __int64)address + size, length);
		}
	};
}