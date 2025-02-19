#pragma once

#include <iostream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <pbc/pbc.h>
#include <fstream>
#include <iostream>

#include "HUE.h"

using namespace std;

// 解密整个文件
void load_file_update(string &input_filename, string &output_filename, RISE &rise, element_t &delta_ke, element_t &new_y)
{
    // 读取所有密文
    std::ifstream in_file(input_filename, std::ios::binary);
    if (!in_file)
    {
        throw std::runtime_error("Failed to open file for reading: " + input_filename);
    }

    // 获取文件大小
    in_file.seekg(0, std::ios::end);
    size_t file_size = in_file.tellg();
    in_file.seekg(0, std::ios::beg);

    // 计算每个密文的大小
    element_t temp_element;
    element_init_G1(temp_element, rise.GetPairing());
    size_t ciphertext_size = element_length_in_bytes_compressed(temp_element) * 2; // 每个元素加密后生成2个密文
    element_clear(temp_element);

    // 计算文件中存储的密文数量
    size_t num_ciphertexts = file_size / ciphertext_size;

    // 读取所有密文并解密
    std::ofstream out_file(output_filename, std::ios::binary);
    if (!out_file)
    {
        throw std::runtime_error("Failed to open file for writing: " + output_filename);
    }

    std::vector<unsigned char> buffer(ciphertext_size);
    for (size_t i = 0; i < num_ciphertexts; ++i)
    {
        // 读取密文
        in_file.read(reinterpret_cast<char *>(buffer.data()), ciphertext_size);

        // 解析密文
        element_t ciphertext[2];
        for (int j = 0; j < 2; ++j)
        {
            element_init_G1(ciphertext[j], rise.GetPairing());
            size_t offset = j * element_length_in_bytes_compressed(ciphertext[j]);
            element_from_bytes_compressed(ciphertext[j], buffer.data() + offset);
        }

        // genxin密文
        element_t update_ciphertext[2];
        element_init_G1(update_ciphertext[0], rise.GetPairing());
        element_init_G1(update_ciphertext[1], rise.GetPairing());
        rise.UpdCiphertext(delta_ke, ciphertext, update_ciphertext, new_y);

        // 将密文写入文件
        for (int j = 0; j < 2; ++j)
        {
            int size = element_length_in_bytes_compressed(update_ciphertext[j]);
            std::vector<unsigned char> buffer(size);
            element_to_bytes_compressed(buffer.data(), update_ciphertext[j]);
            out_file.write(reinterpret_cast<const char *>(buffer.data()), size);
        }

        // 将密文写入文件
        for (int j = 0; j < 2; ++j)
        {
            element_clear(ciphertext[j]);
            element_clear(update_ciphertext[j]);
        }
    }

    in_file.close();
    out_file.close();
}