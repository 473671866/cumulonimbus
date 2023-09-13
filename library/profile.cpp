#include "profile.h"

ProFile::ProFile(std::string file)
{
	char buffer[MAX_PATH]{ NULL };
	GetModuleFileNameA(NULL, buffer, sizeof(buffer));
	this->m_file.append(buffer);

	std::size_t pos = this->m_file.find_last_of('\\');
	if (pos != std::string::npos) this->m_file.erase(pos);

	this->m_file.append("\\");
	this->m_file.append(file);
}

std::list<std::string> ProFile::ReadPrivateProfileSectionNames()
{
	int32_t size = 4096;
	char* buffer = new char[size];
	ZeroMemory(buffer, size);

	int32_t resul = GetPrivateProfileSectionNamesA(buffer, size, this->m_file.c_str());
	while (true) {
		if (resul == (size - 2)) {
			size *= 2;
			delete[] buffer;
			buffer = new char[size];
			ZeroMemory(buffer, size);
		}
		else {
			break;
		}
	}

	std::list<std::string> sections;
	char* segment = buffer;
	while (*segment) {
		sections.push_back(std::string(segment));
		segment += strlen(segment) + 1;
	}

	delete[] buffer;
	return sections;
}

unsigned int ProFile::ReadProfileIntegerA(std::string section, std::string key)
{
	std::lock_guard<std::recursive_mutex> lock(this->m_mtx); // ����
	return GetPrivateProfileIntA(section.c_str(), key.c_str(), 0, this->m_file.c_str());
}

unsigned int ProFile::ReadProfileStringsA(std::string section, std::string key, char* buffer, unsigned long size)
{
	std::lock_guard<std::recursive_mutex> lock(this->m_mtx);
	return GetPrivateProfileStringA(section.c_str(), key.c_str(), NULL, buffer, size, this->m_file.c_str());
}

std::map<std::string, std::string> ProFile::ReadProfileSectionsA(std::string section)
{
	std::lock_guard<std::recursive_mutex> lock(this->m_mtx);

	std::map<std::string, std::string> result;

	unsigned long size = 0x256;
	char* buffer = new char[size];
	ZeroMemory(buffer, size);
	int res = 0;

	while (true) {
		res = GetPrivateProfileSectionA(section.c_str(), buffer, size, this->m_file.c_str());

		if (res == (size - 2)) {
			size *= 2;
			delete[] buffer;
			buffer = new char[size];
			ZeroMemory(buffer, size);
		}
		else {
			break;
		}
	}

	std::string_view str(buffer, res);
	size_t pos = 0;

	while (pos < str.size()) {
		auto end_pos = str.find('\0', pos);
		if (end_pos == std::wstring_view::npos) {
			break;
		}

		std::string_view pair(&str[pos], end_pos - pos);
		auto  eq_pos = pair.find("=");
		if (eq_pos != std::string_view::npos) {
			std::string key(pair.data(), eq_pos);
			std::string value(pair.data() + eq_pos + 1, pair.size() - eq_pos - 1);
			result.emplace(key, value);
		}
		pos = end_pos + 1;
	}

	delete[] buffer;
	return result;
}

bool ProFile::WriteProfileStringsA(std::string section, std::string key, std::string buffer)
{
	std::lock_guard<std::recursive_mutex> lock(this->m_mtx);
	return WritePrivateProfileStringA(section.c_str(), key.c_str(), buffer.c_str(), this->m_file.c_str());
}

bool ProFile::WriteProfileIntegerA(std::string section, std::string key, int32_t contect)
{
	std::lock_guard<std::recursive_mutex> lock(this->m_mtx);
	char buffer[0x32]{ NULL };
	sprintf_s(buffer, "%d", contect);
	return WritePrivateProfileStringA(section.c_str(), key.c_str(), buffer, this->m_file.c_str());
}

bool ProFile::WriteProfileSectonsA(std::string section, std::string buffer)
{
	std::lock_guard<std::recursive_mutex> lock(this->m_mtx);
	return WritePrivateProfileSectionA(section.c_str(), buffer.c_str(), this->m_file.c_str());
}

bool ProFile::DeleteProfileString(std::string section, std::string key)
{
	std::lock_guard<std::recursive_mutex> lock(this->m_mtx);
	return WritePrivateProfileStringA(section.c_str(), key.c_str(), NULL, this->m_file.c_str());
}

bool ProFile::DeleteProfileSection(std::string section)
{
	return WritePrivateProfileStringA(section.c_str(), NULL, NULL, this->m_file.c_str());
}