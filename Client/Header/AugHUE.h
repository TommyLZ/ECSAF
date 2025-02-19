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

void convert_G1_to_Zr(element_t &out, element_t &hash, pairing_t &pairing)
{
    // 获取 G1 元素的字节表示
    unsigned char hash_bytes[128]; // 足够存储 G1 元素
    int hash_size = element_to_bytes(hash_bytes, hash);

    // 用 element_from_hash 映射到 Zr
    element_init_Zr(out, pairing);
    element_from_hash(out, hash_bytes, hash_size);
}

// 将 element_t 数组写入文件
void write_elements_to_file(const std::string &filename, element_t a[], element_t b)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
        return;
    }

    for (size_t i = 0; i < 2; ++i)
    {
        // 将 element_t 转换为字节流
        int len_a = element_length_in_bytes(a[i]);
        std::vector<unsigned char> data_a(len_a);
        element_to_bytes(data_a.data(), a[i]);
        file.write(reinterpret_cast<const char *>(data_a.data()), len_a);
    }

    int len_b = element_length_in_bytes(b);
    std::vector<unsigned char> data_b(len_b);
    element_to_bytes(data_b.data(), b);
    file.write(reinterpret_cast<const char *>(data_b.data()), len_b);

    file.close();
    std::cout << "Data written to file: " << filename << std::endl;
}

// 从文件中读取 element_t 数组
void read_elements_from_file(string &filename, element_t a[], element_t b, pairing_t &pairing)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file for reading: " << filename << std::endl;
        return;
    }

    for (size_t i = 0; i < 2; ++i)
    {
        // 从字节流中恢复 element_t
        int len_a = element_length_in_bytes(a[i]);
        std::vector<unsigned char> data_a(len_a);
        file.read(reinterpret_cast<char *>(data_a.data()), len_a);
        element_from_bytes(a[i], data_a.data());
    }

    int len_b = element_length_in_bytes(b);
    std::vector<unsigned char> data_b(len_b);
    file.read(reinterpret_cast<char *>(data_b.data()), len_b);
    element_from_bytes(b, data_b.data());

    file.close();
    std::cout << "Data read from file: " << filename << std::endl;
}

#include <pbc/pbc.h>
#include <fstream>
#include <vector>
#include <iostream>

void save_label_to_file(string &filename, element_t C, element_t r) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        return;
    }

    // 获取 C 的二进制表示
    int c_size = element_length_in_bytes(C);
    std::vector<unsigned char> c_buf(c_size);
    element_to_bytes(c_buf.data(), C);

    // 获取 r 的二进制表示
    int r_size = element_length_in_bytes(r);
    std::vector<unsigned char> r_buf(r_size);
    element_to_bytes(r_buf.data(), r);

    // 写入 C 的大小和数据
    file.write(reinterpret_cast<const char *>(&c_size), sizeof(c_size));
    file.write(reinterpret_cast<const char *>(c_buf.data()), c_size);

    // 写入 r 的大小和数据
    file.write(reinterpret_cast<const char *>(&r_size), sizeof(r_size));
    file.write(reinterpret_cast<const char *>(r_buf.data()), r_size);

    file.close();
}

void load_label_from_file(const std::string &filename, pairing_t pairing, element_t C, element_t r) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for reading: " << filename << std::endl;
        return;
    }

    // 读取 C 的大小
    int c_size;
    file.read(reinterpret_cast<char *>(&c_size), sizeof(c_size));
    std::vector<unsigned char> c_buf(c_size);
    file.read(reinterpret_cast<char *>(c_buf.data()), c_size);

    // 读取 r 的大小
    int r_size;
    file.read(reinterpret_cast<char *>(&r_size), sizeof(r_size));
    std::vector<unsigned char> r_buf(r_size);
    file.read(reinterpret_cast<char *>(r_buf.data()), r_size);

    file.close();

    // 解析回 C 和 r
    element_init_G1(C, pairing);
    element_from_bytes(C, c_buf.data());

    element_init_Zr(r, pairing);
    element_from_bytes(r, r_buf.data());
}


// **********************************************************************************

// 保存元素到文件（追加模式）
void save_element_to_file(const std::string &filename, element_t &element)
{
    std::ofstream file(filename, std::ios::binary | std::ios::app);
    if (!file)
    {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    int element_size = element_length_in_bytes(element);
    std::vector<unsigned char> buffer(element_size);
    element_to_bytes(buffer.data(), element);
    file.write(reinterpret_cast<const char *>(buffer.data()), element_size);
}

// 从文件中读取所有元素
std::vector<element_t> load_elements_from_file(const std::string &filename, pairing_t &pairing)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
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

    for (size_t i = 0; i < num_elements; ++i)
    {
        element_init_G1(elements[i], pairing);
        file.read(reinterpret_cast<char *>(buffer.data()), element_size);
        element_from_bytes(elements[i], buffer.data());
    }

    file.close();
    return elements;
}

// 加密整个文件
void encrypt_file(const std::string &input_filename, const std::string &output_filename, RISE &rise)
{
    // 读取所有元素
    std::vector<element_t> elements = load_elements_from_file(input_filename, rise.GetPairing());

    // 加密每个元素并写入文件
    std::ofstream out_file(output_filename, std::ios::binary);
    if (!out_file)
    {
        throw std::runtime_error("Failed to open file for writing: " + output_filename);
    }

    for (size_t i = 0; i < elements.size(); ++i)
    {
        element_t ciphertext[2];
        for (int j = 0; j < 2; ++j)
        {
            element_init_G1(ciphertext[j], rise.GetPairing());
        }

        // 加密元素
        rise.EncryptElement(elements[i], ciphertext);

        // 将密文写入文件
        for (int j = 0; j < 2; ++j)
        {
            int size = element_length_in_bytes_compressed(ciphertext[j]);
            std::vector<unsigned char> buffer(size);
            element_to_bytes_compressed(buffer.data(), ciphertext[j]);
            out_file.write(reinterpret_cast<const char *>(buffer.data()), size);
        }

        // 释放密文内存
        for (int j = 0; j < 2; ++j)
        {
            element_clear(ciphertext[j]);
        }
    }

    out_file.close();

    // 释放元素内存
    for (size_t i = 0; i < elements.size(); ++i)
    {
        element_clear(elements[i]);
    }
}

// 解密整个文件
void decrypt_file(const std::string &input_filename, const std::string &output_filename, RISE &rise)
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
        for (int j = 0; j < 2; ++j)
        {
            element_clear(ciphertext[j]);
        }
        element_clear(plaintext);
    }

    in_file.close();
    out_file.close();
}

// 生成多个文件
void generate_files(const std::string &folder_path, size_t num_files, size_t target_file_size, RISE &rise)
{
    element_t sample_element;
    element_init_G1(sample_element, rise.GetPairing());
    element_random(sample_element); // 随机生成一个元素
    size_t element_size = element_length_in_bytes(sample_element);
    size_t num_elements = target_file_size / element_size;

    for (size_t i = 0; i < num_files; ++i)
    {
        std::string filename = folder_path + "/element_" + std::to_string(i) + ".dat";
        for (size_t j = 0; j < num_elements; ++j)
        {
            save_element_to_file(filename, sample_element);
        }
    }
    element_clear(sample_element);
}

// 加密文件夹中的所有文件
void encrypt_folder(const std::string &input_folder, const std::string &output_folder, RISE &rise)
{
    int count = 0;
    for (const auto &entry : fs::directory_iterator(input_folder))
    {
        if (entry.is_regular_file())
        {
            std::string input_filename = entry.path().string();
            std::string output_filename = output_folder + "/file" + to_string(count) + "_cipher.dat";
            cout << "Encrypting: " << input_filename << " -> " << output_filename << endl;
            encrypt_file(input_filename, output_filename, rise);
            count++;
        }
    }
}

// 解密文件夹中的所有文件
void decrypt_folder(const std::string &input_folder, const std::string &output_folder, RISE &rise)
{
    int count = 0;
    for (const auto &entry : fs::directory_iterator(input_folder))
    {
        if (entry.is_regular_file())
        {
            std::string input_filename = entry.path().string();
            std::string output_filename = output_folder + "/file" + to_string(count) + "_plain.dat";
            cout << "Decrypting: " << input_filename << " -> " << output_filename << endl;
            decrypt_file(input_filename, output_filename, rise);
            count++;
        }
    }
}