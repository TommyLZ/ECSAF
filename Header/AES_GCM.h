#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip> // 用于打印十六进制
#include <cstring>
#include <filesystem>

class AESGCM {
private:
    static constexpr size_t AES_KEY_SIZE = 32;
    static constexpr size_t GCM_IV_SIZE = 12;
    static constexpr size_t GCM_TAG_SIZE = 16;

    unsigned char key[AES_KEY_SIZE] = {0};
    unsigned char iv[GCM_IV_SIZE] = {0};

    const std::string iv_file = "../Key/aes_gcm_iv.dat";

    void save_to_file(const std::string& file_path, const unsigned char* data, size_t size) {
        std::ofstream file(file_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for writing: " + file_path);
        }
        file.write(reinterpret_cast<const char*>(data), size);
    }

    void load_from_file(const std::string& file_path, unsigned char* data, size_t size) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open file for reading: " + file_path);
        }
        file.read(reinterpret_cast<char*>(data), size);
        if (file.gcount() != static_cast<std::streamsize>(size)) {
            throw std::runtime_error("Failed to read the expected size from file: " + file_path);
        }
    }

    void print_hex(const std::string& label, const unsigned char* data, size_t size) {
        std::cout << label << ": ";
        for (size_t i = 0; i < size; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        }
        std::cout << std::dec << std::endl;
    }

public:
    static constexpr size_t get_tag_size() { return GCM_TAG_SIZE; }

    AESGCM() {
        std::filesystem::create_directories("./Key");
        try {
            load_from_file(iv_file, iv, GCM_IV_SIZE);
        } catch (...) {
            RAND_bytes(iv, GCM_IV_SIZE);
            save_to_file(iv_file, iv, GCM_IV_SIZE);
        }
    }

    void set_key(const vector<unsigned char>& new_key) {
        if (new_key.size() != AES_KEY_SIZE) {
            throw runtime_error("Invalid key size: Expected " + std::to_string(AES_KEY_SIZE) + " bytes.");
        }
        memcpy(key, new_key.data(), AES_KEY_SIZE);
    }

    void set_key(const std::string& key_file_path) {
        std::ifstream key_file(key_file_path, std::ios::binary);
        if (!key_file) {
            throw std::runtime_error("无法打开密钥文件: " + key_file_path);
        }

        // 读取密钥数据
        std::vector<unsigned char> file_key(AES_KEY_SIZE);
        key_file.read(reinterpret_cast<char*>(file_key.data()), AES_KEY_SIZE);

        // 检查是否读取了足够的字节
        if (key_file.gcount() != AES_KEY_SIZE) {
            throw std::runtime_error("密钥文件大小无效: 预期 " + std::to_string(AES_KEY_SIZE) + " 字节。");
        }

        // 将密钥复制到内部存储
        memcpy(key, file_key.data(), AES_KEY_SIZE);
    }

    bool encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* ciphertext, unsigned char* tag) {
        print_hex("[Encrypt] Plaintext", plaintext, plaintext_len);
        print_hex("[Encrypt] Key", key, AES_KEY_SIZE);
        print_hex("[Encrypt] IV", iv, GCM_IV_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

        int len;
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
        int ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag);

        print_hex("[Encrypt] Ciphertext", ciphertext, ciphertext_len);
        print_hex("[Encrypt] Tag", tag, GCM_TAG_SIZE);

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    bool decrypt(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* tag, unsigned char* plaintext) {
        print_hex("[Decrypt] Ciphertext", ciphertext, ciphertext_len);
        print_hex("[Decrypt] Key", key, AES_KEY_SIZE);
        print_hex("[Decrypt] IV", iv, GCM_IV_SIZE);
        print_hex("[Decrypt] Tag", tag, GCM_TAG_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag);

        int len;
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        int plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        plaintext_len += len;

        print_hex("[Decrypt] Plaintext", plaintext, plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
};