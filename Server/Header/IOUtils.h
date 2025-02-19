#pragma once
#include <iostream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <pbc/pbc.h>
#include <fstream>
#include <iostream>

# define BUFFER_SIZE 1024

using namespace std;

    // Helper function to read k from file
    bool readKFromFile(BIGNUM* k, const string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (file.is_open()) {
            file >> std::noskipws;
            // Read the size of the k value
            int k_size;
            file.read(reinterpret_cast<char*>(&k_size), sizeof(k_size));
            if (k_size > 0) {
                unsigned char* k_data = new unsigned char[k_size];
                file.read(reinterpret_cast<char*>(k_data), k_size);
                BN_bin2bn(k_data, k_size, k);
                delete[] k_data;
                file.close();
                return true;
            }
            file.close();
        }
        return false;
    }

    // Helper function to generate and store k to file
    void writeInFile(BIGNUM* k, const string& filename) {
        // do {
        //     BN_rand_range(k, order);  // Generate random k such that 0 <= k < order
        // } while (BN_is_zero(k));

        // Save k to file
        std::ofstream file(filename, std::ios::binary);
        if (file.is_open()) {
            int k_size = BN_num_bytes(k);
            file.write(reinterpret_cast<char*>(&k_size), sizeof(k_size));
            unsigned char* k_data = new unsigned char[k_size];
            BN_bn2bin(k, k_data);
            file.write(reinterpret_cast<char*>(k_data), k_size);
            delete[] k_data;
            file.close();
        }
    }

void writeECPointToFile(const EC_GROUP* group, const EC_POINT* point, const std::string& file_name, BN_CTX* ctx) {
    // 打开文件以二进制模式写入
    std::ofstream file(file_name, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for writing: " << file_name << std::endl;
        return;
    }

    // 获取点的字节表示长度
    size_t point_size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
    if (point_size == 0) {
        std::cerr << "Failed to calculate EC_POINT size!" << std::endl;
        return;
    }

    // 分配字节数组并转换点
    unsigned char* point_data = new unsigned char[point_size];
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, point_data, point_size, ctx);

    // 写入点的大小和数据到文件
    file.write(reinterpret_cast<const char*>(&point_size), sizeof(point_size));
    file.write(reinterpret_cast<const char*>(point_data), point_size);

    // 清理资源
    delete[] point_data;
    file.close();
    std::cout << "EC_POINT saved to file: " << file_name << std::endl;
}


bool readECPointFromFile(const EC_GROUP* group, EC_POINT* point, const std::string& file_name, BN_CTX* ctx) {
    // 打开文件以二进制模式读取
    std::ifstream file(file_name, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for reading: " << file_name << std::endl;
        return false;
    }

    // 读取点的大小
    size_t point_size = 0;
    file.read(reinterpret_cast<char*>(&point_size), sizeof(point_size));
    if (point_size == 0) {
        std::cerr << "Invalid EC_POINT size in file!" << std::endl;
        return false;
    }

    // 分配字节数组并读取点数据
    unsigned char* point_data = new unsigned char[point_size];
    file.read(reinterpret_cast<char*>(point_data), point_size);

    // 从字节数组恢复 EC_POINT
    if (EC_POINT_oct2point(group, point, point_data, point_size, ctx) != 1) {
        std::cerr << "Failed to restore EC_POINT from file!" << std::endl;
        delete[] point_data;
        return false;
    }

    delete[] point_data;
    file.close();
    std::cout << "EC_POINT restored from file: " << file_name << std::endl;
    return true;
}


// Base64 编码
std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // 避免换行符
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

// Base64 解码
std::vector<unsigned char> base64_decode(const std::string& encoded) {
    BIO* bio, * b64;
    int decodeLen = encoded.length();
    std::vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decodedSize = BIO_read(bio, buffer.data(), buffer.size());
    BIO_free_all(bio);

    buffer.resize(decodedSize);
    return buffer;
}

    // Function to read a key from a file
    void load_key_from_file(const std::string& file_path, element_t& key, pairing_t& pairing) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open key file: " + file_path);
        }

        std::string key_str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        // 确保 secret_key 是 Zr 类型，而 public_key 是 G2 类型
        if (file_path.find("secret") != std::string::npos) {
            element_init_Zr(key, pairing); // 私钥是 Zr 群的元素
        } else {
            element_init_G2(key, pairing); // 公钥是 G2 群的元素
        }
        element_set_str(key, key_str.c_str(), 10);
    }

  // Function to save a key to a file
    void save_key_to_file(const std::string& file_path, element_t& key) {
        std::ofstream file(file_path, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("Failed to open key file for writing: " + file_path);
        }

        char key_str[1024];
        element_snprint(key_str, sizeof(key_str), key);
        file.write(key_str, strlen(key_str));
        if (!file) {
            throw std::runtime_error("Failed to write key to file: " + file_path);
        }
    }

    void save_gen_to_file(const std::string& filename, element_t& key) {
        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }
        int key_size = element_length_in_bytes(key);
        std::vector<unsigned char> buffer(key_size);
        element_to_bytes(buffer.data(), key);
        file.write(reinterpret_cast<const char*>(buffer.data()), key_size);
    }

    void load_gen_from_file(const std::string& filename, element_t& key) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for reading: " + filename);
        }
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<unsigned char> buffer(size);
        file.read(reinterpret_cast<char*>(buffer.data()), size);
        element_from_bytes(key, buffer.data());
    }

// 发送单个文件的函数
void sendFile(int client_socket, const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return;
    }

    // 获取文件大小
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // 发送文件大小
    if (send(client_socket, &fileSize, sizeof(fileSize), 0) < 0) {
        std::cerr << "Failed to send file size!" << std::endl;
        return;
    }

    // 发送文件内容
    char buffer[BUFFER_SIZE];
    size_t totalSent = 0;
    while (totalSent < fileSize) {
        file.read(buffer, BUFFER_SIZE);
        size_t bytesRead = file.gcount();
        ssize_t bytesSent = send(client_socket, buffer, bytesRead, 0);
        if (bytesSent < 0) {
            std::cerr << "Failed to send file data!" << std::endl;
            return;
        }
        totalSent += bytesSent;
    }

    std::cout << "File sent successfully: " << filePath << std::endl;
    file.close();
}

// 获取文件夹中的所有文件路径
std::vector<std::string> getFilesInDirectory(const std::string& folderPath) {
    std::vector<std::string> files;
    for (const auto& entry : filesystem::directory_iterator(folderPath)) {
        if (entry.is_regular_file()) { // 只处理普通文件
            files.push_back(entry.path().string());
        }
    }
    return files;
}


// 接收单个文件的函数
void receiveFile(int server_socket, const std::string& filePath) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to create file: " << filePath << std::endl;
        return;
    }

    // 接收文件大小
    size_t fileSize;
    if (recv(server_socket, &fileSize, sizeof(fileSize), 0) < 0) {
        std::cerr << "Failed to receive file size!" << std::endl;
        return;
    }

    // 接收文件内容
    char buffer[BUFFER_SIZE];
    size_t totalReceived = 0;
    while (totalReceived < fileSize) {
        ssize_t bytesReceived = recv(server_socket, buffer, BUFFER_SIZE, 0);
        if (bytesReceived < 0) {
            std::cerr << "Failed to receive file data!" << std::endl;
            return;
        }
        file.write(buffer, bytesReceived);
        totalReceived += bytesReceived;
    }

    std::cout << "File received successfully: " << filePath << std::endl;
    file.close();
}

// 存储 G1 元素到文件
void save_G1element_to_file(const std::string& filename, element_t& element) {
    std::ofstream out_file(filename, std::ios::binary);
    if (!out_file) {
        throw std::runtime_error("无法打开文件进行写入");
    }

    // 获取 G1 元素的字节表示
    int size = element_length_in_bytes_compressed(element);
    std::vector<unsigned char> buffer(size);
    element_to_bytes_compressed(buffer.data(), element);

    // 先写入大小，再写入数据
    out_file.write(reinterpret_cast<const char*>(&size), sizeof(size));
    out_file.write(reinterpret_cast<const char*>(buffer.data()), size);
    out_file.close();
}

// 从文件中读取 G1 元素
void load_G1element_from_file(const std::string& filename, element_t& element, pairing_t& pairing) {
    std::ifstream in_file(filename, std::ios::binary);
    if (!in_file) {
        throw std::runtime_error("无法打开文件进行读取");
    }

    // 读取大小
    int size;
    in_file.read(reinterpret_cast<char*>(&size), sizeof(size));
    std::vector<unsigned char> buffer(size);
    in_file.read(reinterpret_cast<char*>(buffer.data()), size);
    in_file.close();

    // 初始化 G1 元素并恢复
    element_init_G1(element, pairing);
    element_from_bytes_compressed(element, buffer.data());
}

// 存储 G1 元素数组到文件
void save_G1elementVec_to_file(const std::string& filename, element_t* elements, int count) {
    std::ofstream out_file(filename, std::ios::binary);
    if (!out_file) {
        throw std::runtime_error("无法打开文件进行写入");
    }
    
    // 先写入元素个数
    out_file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    for (int i = 0; i < count; ++i) {
        int size = element_length_in_bytes_compressed(elements[i]);
        std::vector<unsigned char> buffer(size);
        element_to_bytes_compressed(buffer.data(), elements[i]);
        
        // 依次写入大小和数据
        out_file.write(reinterpret_cast<const char*>(&size), sizeof(size));
        out_file.write(reinterpret_cast<const char*>(buffer.data()), size);
    }
    out_file.close();
}

// 从文件中读取 G1 元素数组
void load_G1elementVec_from_file(const std::string& filename, element_t* elements, int& count, pairing_t& pairing) {
    std::ifstream in_file(filename, std::ios::binary);
    if (!in_file) {
        throw std::runtime_error("无法打开文件进行读取");
    }
    
    // 读取元素个数
    in_file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    for (int i = 0; i < count; ++i) {
        int size;
        in_file.read(reinterpret_cast<char*>(&size), sizeof(size));
        std::vector<unsigned char> buffer(size);
        in_file.read(reinterpret_cast<char*>(buffer.data()), size);
        
        element_init_G1(elements[i], pairing);
        element_from_bytes_compressed(elements[i], buffer.data());
    }
    in_file.close();
}