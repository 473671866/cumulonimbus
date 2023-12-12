#pragma once
#include "../Standard/base.h"

namespace utils {
	enum class BuildNumber : UINT32 {
		Unknown,
		WindowsXP,                  // 5.1.2600
		WindowsXP64,                // 5.2.3790
		WindowsVista,               // 6.0.6000
		WindowsVista_SP1,           // 6.0.6001
		WindowsVista_SP2,           // 6.0.6002
		Windows7,                   // 6.1.7600
		Windows7_SP1,               // 6.1.7601
		Windows8,                   // 6.2.9200
		Windows8_1,                 // 6.3.9600
		Windows10,
		Windows10_1507 = Windows10, // 10.0.10240
		Windows10_1511,             // 10.0.10586
		Windows10_1607,             // 10.0.14393
		Windows10_1703,             // 10.0.15063
		Windows10_1709,             // 10.0.16299
		Windows10_1803,             // 10.0.17134
		Windows10_1809,             // 10.0.17763
		Windows10_1903,             // 10.0.18362
		Windows10_1909,             // 10.0.18363
		Windows10_2004,             // 10.0.19041
		Windows10_2009,             // 10.0.19042
		Windows10_2104,				// 10.0.19044
		Windows10_2110,				// 10.0.19045
		WindowsMax,
	};

	class version :public Singleton<version> {
	public:
		version() {
			RTL_OSVERSIONINFOW system_version{ NULL };
			RtlGetVersion(&system_version);

			switch (system_version.dwBuildNumber) {
			default:
				this->number = BuildNumber::Unknown;
				break;
			case 2600:
				this->number = BuildNumber::WindowsXP;
				break;
			case 3790:
				this->number = BuildNumber::WindowsXP64;
				break;
			case 6000:
				this->number = BuildNumber::WindowsVista;
				break;
			case 6001:
				this->number = BuildNumber::WindowsVista_SP1;
				break;
			case 6002:
				this->number = BuildNumber::WindowsVista_SP2;
				break;
			case 7600:
				this->number = BuildNumber::Windows7;
				break;
			case 7601:
				this->number = BuildNumber::Windows7_SP1;
				break;
			case 9200:
				this->number = BuildNumber::Windows8;
				break;
			case 9600:
				this->number = BuildNumber::Windows8_1;
				break;
			case 10240:
				this->number = BuildNumber::Windows10;
				break;
			case 10586:
				this->number = BuildNumber::Windows10_1511;
				break;
			case 14393:
				this->number = BuildNumber::Windows10_1607;
				break;
			case 15063:
				this->number = BuildNumber::Windows10_1703;
				break;
			case 16299:
				this->number = BuildNumber::Windows10_1709;
				break;
			case 17134:
				this->number = BuildNumber::Windows10_1803;
				break;
			case 17763:
				this->number = BuildNumber::Windows10_1809;
				break;
			case 18362:
				this->number = BuildNumber::Windows10_1903;
				break;
			case 18363:
				this->number = BuildNumber::Windows10_1909;
				break;
			case 19041:
				this->number = BuildNumber::Windows10_2004;
				break;
			case 19042:
				this->number = BuildNumber::Windows10_2009;
				break;
			case 19044:
				this->number = BuildNumber::Windows10_2104;
				break;
			case 19045:
				this->number = BuildNumber::Windows10_2110;
				break;
			}
		}

		BuildNumber GetSystemVersion() {
			return this->number;
		}

		bool windows_7() {
			return (this->number == BuildNumber::Windows7 || this->number == BuildNumber::Windows7_SP1);
		}

		bool windows_10() {
			return this->number >= BuildNumber::Windows10;
		}

	private:
		BuildNumber number;
	};
}