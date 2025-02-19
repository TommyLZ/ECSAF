#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <pbc/pbc.h>
#include <filesystem>
#include <pbc/pbc_test.h>
#include "HUE.h"

using namespace std;
namespace fs = filesystem;

// 保存元素到文件（追加模式）
void save_element_to_file(const std::string &filename, element_t &element) {
    std::ofstream file(filename, std::ios::binary | std::ios::app);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    int element_size = element_length_in_bytes(element);
    std::vector<unsigned char> buffer(element_size);
    element_to_bytes(buffer.data(), element);
    file.write(reinterpret_cast<const char *>(buffer.data()), element_size);
}

// 从文件中读取所有元素
std::vector<element_t> load_elements_from_file(const std::string &filename, pairing_t &pairing) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    // 获取文件大小
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    // 计算每个元素的大小
    element_t temp_element;
    element_init_G1(temp_element, pairing);
    size_t element_size = element_length_in_bytes(temp_element);
    element_clear(temp_element);

    // 计算文件中存储的元素数量
    size_t num_elements = file_size / element_size;

    // 读取所有元素
    std::vector<element_t> elements(num_elements);
    std::vector<unsigned char> buffer(element_size);

    for (size_t i = 0; i < num_elements; ++i) {
        element_init_G1(elements[i], pairing);
        file.read(reinterpret_cast<char *>(buffer.data()), element_size);
        element_from_bytes(elements[i], buffer.data());
    }

    file.close();
    return elements;
}

// 加密整个文件
void encrypt_file(const std::string &input_filename, const std::string &output_filename, RISE &rise) {
    // 读取所有元素
    std::vector<element_t> elements = load_elements_from_file(input_filename, rise.GetPairing());

    // 加密每个元素并写入文件
    std::ofstream out_file(output_filename, std::ios::binary);
    if (!out_file) {
        throw std::runtime_error("Failed to open file for writing: " + output_filename);
    }

    for (size_t i = 0; i < elements.size(); ++i) {
        element_t ciphertext[2];
        for (int j = 0; j < 2; ++j) {
            element_init_G1(ciphertext[j], rise.GetPairing());
        }

        // 加密元素
        rise.EncryptElement(elements[i], ciphertext);

        // 将密文写入文件
        for (int j = 0; j < 2; ++j) {
            int size = element_length_in_bytes_compressed(ciphertext[j]);
            std::vector<unsigned char> buffer(size);
            element_to_bytes_compressed(buffer.data(), ciphertext[j]);
            out_file.write(reinterpret_cast<const char *>(buffer.data()), size);
        }

        // 释放密文内存
        for (int j = 0; j < 2; ++j) {
            element_clear(ciphertext[j]);
        }
    }

    out_file.close();

    // 释放元素内存
    for (size_t i = 0; i < elements.size(); ++i) {
        element_clear(elements[i]);
    }
}

// 解密整个文件
void decrypt_file(const std::string &input_filename, const std::string &output_filename, RISE &rise) {
    // 读取所有密文
    std::ifstream in_file(input_filename, std::ios::binary);
    if (!in_file) {
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
    if (!out_file) {
        throw std::runtime_error("Failed to open file for writing: " + output_filename);
    }

    std::vector<unsigned char> buffer(ciphertext_size);
    for (size_t i = 0; i < num_ciphertexts; ++i) {
        // 读取密文
        in_file.read(reinterpret_cast<char *>(buffer.data()), ciphertext_size);

        // 解析密文
        element_t ciphertext[2];
        for (int j = 0; j < 2; ++j) {
            element_init_G1(ciphertext[j], rise.GetPairing());
            size_t offset = j * element_length_in_bytes_compressed(ciphertext[j]);
            element_from_bytes_compressed(ciphertext[j], buffer.data() + offset);
        }

        // 解密密文
        element_t plaintext;
        element_init_G1(plaintext, rise.GetPairing());
        rise.DecryptElement(ciphertext, plaintext);

        // 将解密后的元素写入文件
        int size = element_length_in_bytes(plaintext);
        std::vector<unsigned char> plaintext_buffer(size);
        element_to_bytes(plaintext_buffer.data(), plaintext);
        out_file.write(reinterpret_cast<const char *>(plaintext_buffer.data()), size);

        // 释放内存
        for (int j = 0; j < 2; ++j) {
            element_clear(ciphertext[j]);
        }
        element_clear(plaintext);
    }

    in_file.close();
    out_file.close();
}

// 生成多个文件
void generate_files(const std::string &folder_path, size_t num_files, size_t target_file_size, RISE &rise) {
    element_t sample_element;
    element_init_G1(sample_element, rise.GetPairing());
    element_random(sample_element); // 随机生成一个元素
    size_t element_size = element_length_in_bytes(sample_element);
    size_t num_elements = target_file_size / element_size;

    for (size_t i = 0; i < num_files; ++i) {
        std::string filename = folder_path + "/element_" + std::to_string(i) + ".dat";
        for (size_t j = 0; j < num_elements; ++j) {
            save_element_to_file(filename, sample_element);
        }
    }
    element_clear(sample_element);
}

// 加密文件夹中的所有文件
void encrypt_folder(const std::string &input_folder, const std::string &output_folder, RISE &rise) {
    int count = 0;
    for (const auto &entry : fs::directory_iterator(input_folder)) {
        if (entry.is_regular_file()) {
            std::string input_filename = entry.path().string();
            std::string output_filename = output_folder + "/file" + to_string(count) + "_cipher.dat" ;
            cout << "Encrypting: " << input_filename << " -> " << output_filename << endl;
            encrypt_file(input_filename, output_filename, rise);
            count ++;
        }
    }
}

// 解密文件夹中的所有文件
void decrypt_folder(const std::string &input_folder, const std::string &output_folder, RISE &rise) {
    int count = 0;
    for (const auto &entry : fs::directory_iterator(input_folder)) {
        if (entry.is_regular_file()) {
            std::string input_filename = entry.path().string();
            std::string output_filename = output_folder + "/file" + to_string(count) + "_plain.dat" ;
             cout << "Decrypting: " << input_filename << " -> " << output_filename << endl;
            decrypt_file(input_filename, output_filename, rise);
            count ++;
        }
    }
}