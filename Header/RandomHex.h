#pragma once
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <string>

// std::string generateHex64() {
//     const size_t length = 64; // 长度为64的16进制数
//     std::ostringstream oss;
//     std::random_device rd;  // 用于产生随机数种子
//     std::mt19937 gen(rd()); // 使用Mersenne Twister引擎
//     std::uniform_int_distribution<int> dis(0, 15); // 16进制范围 [0, 15]

//     for (size_t i = 0; i < length; ++i) {
//         int randomValue = dis(gen);
//         oss << std::hex << std::nouppercase << randomValue; // 转换为小写16进制字符
//     }

//     return oss.str();
// }

std::vector<unsigned char> generateHex64() {
    const size_t length = 32; // 生成 32 字节（64 个十六进制字符）
    std::vector<unsigned char> bytes(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255); // 0x00 - 0xFF

    for (size_t i = 0; i < length; ++i) {
        bytes[i] = static_cast<unsigned char>(dis(gen));
    }

    return bytes;
}

// int main() {
//     std::string hex64 = generateHex64();
//     std::cout << "随机生成的长度为64的16进制数: " << hex64 << std::endl;
//     return 0;
// }