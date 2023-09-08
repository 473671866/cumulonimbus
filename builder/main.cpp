#include <iostream>
#include <fstream>
#include <filesystem>

int main(int arg, char** argv) {
	if (arg < 2) {
		return -1;
	}

	//读
	std::filesystem::path file_path(argv[1]);
	if (!std::filesystem::exists(file_path)) {
		std::cout << "文件不存在\n";
		system("pause");
		return -2;
	}

	auto filesize = std::filesystem::file_size(file_path);
	std::ifstream istream(file_path, std::ios::binary);
	if (istream.is_open() == false) {
		std::cout << "打开文件失败\n";
		system("pause");
		return -3;
	}

	unsigned char* filebuffer = new unsigned char[filesize];
	istream.read((char*)filebuffer, filesize);
	if (istream.fail()) {
		std::cout << "读取文件失败\n";
		system("pause");
		return -4;
	}
	istream.close();

	//写
	file_path.replace_extension(".hpp");
	std::ofstream ostream(file_path, std::ios::binary);
	if (!ostream.is_open()) {
		std::cout << "创建文件失败\n";
		system("pause");
		return -5;
	}

	ostream << "#pragma once\n";
	ostream << "unsigned char " << file_path.stem().string() << "[" << filesize << "] = {" << std::endl;
	ostream << "\t";
	for (int i = 0; i < filesize; i++) {
		filebuffer[i] ^= 0xA;
		filebuffer[i] ^= 0xF;
		ostream << "0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(filebuffer[i]) << ", ";
		if ((i + 1) % 20 == 0) {
			ostream << "\r\n\t";
		}
	}
	ostream << "\r\n};";
	ostream.close();

	delete[] filebuffer;
	return 0;
}