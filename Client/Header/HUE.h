#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <pbc/pbc.h>
#include <filesystem>
#include <pbc/pbc_test.h>

using namespace std;
namespace fs = filesystem;

// RISE 方案类
class RISE {
private:
    pairing_t pairing; // PBC 配对对象
    element_t g;       // 循环群的生成元
    element_t ke;      // 加密密钥
    const string g_file_path = "../Key/g.dat"; // Path to store g

public:
    // 构造函数：初始化系统
    RISE() {
        // 初始化配对参数（使用预定义的参数）
        const std::string param_file = "../Param/a.param";

        // Load pairing parameters from file
        char param[1024];
        std::ifstream file(param_file, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open parameter file: " + param_file);
        }
        size_t count = file.readsome(param, sizeof(param));
        if (count == 0) {
            throw std::runtime_error("Failed to read parameter file: " + param_file);
        }
        pairing_init_set_buf(pairing, param, count);

        element_init_G1(g, pairing);
        element_init_Zr(ke, pairing);

        // Load or generate g
        if (fs::exists(g_file_path)) {
            load_gen_from_file(g_file_path, g);
            element_printf("********The initialization of g is %B\n", g);
        } else {
            element_random(g);
            save_gen_to_file(g_file_path, g);
        }
    }

    // 设置加密密钥
    void SetKey(element_t& key) {
        element_set(ke, key);
    }

    pairing_t& GetPairing() {
        return pairing;
    }

    element_t& GetGenerator() {
        return g;
    }

    void EncryptElement(element_t& plaintext, element_t ciphertext[]) {
        element_t r, y, C1, C2;
        element_init_Zr(r, pairing);
        element_init_G1(y, pairing);
        element_init_G1(C1, pairing);
        element_init_G1(C2, pairing);

        // 计算 y = g^{ke}
        element_pow_zn(y, g, ke);

        // 随机选择 r
        element_random(r);

        // 计算 C1 = y^r
        element_pow_zn(C1, y, r);

        // 计算 C2 = g^r * plaintext
        element_pow_zn(C2, g, r);
        element_mul(C2, C2, plaintext);

        // 将密文存储到 vector 中
        element_set(ciphertext[0], C1);
        element_set(ciphertext[1], C2);

        // 释放临时变量
        element_clear(r);
        element_clear(y);
    }

    void DecryptElement(element_t ciphertext[], element_t& plaintext) {
        element_t C1, C2;
        element_init_G1(C1, pairing);
        element_init_G1(C2, pairing);
        element_set(C1, ciphertext[0]);
        element_set(C2, ciphertext[1]);

        element_t temp;
        element_init_G1(temp, pairing);

        // 计算 plaintext = C2 * C1^{-1/ke}
        element_t ke_inv;
        element_init_Zr(ke_inv, pairing);
        element_invert(ke_inv, ke);  // 计算 ke 的逆元
        element_pow_zn(temp, C1, ke_inv); // 计算 C1^{1/ke}
        element_invert(temp, temp);
        element_mul(plaintext, C2, temp);

        // 释放临时变量
        element_clear(temp);
    }

        // 密钥更新算法 RISE.Next
    void NextKey(element_t& new_ke, element_t& old_ke, element_t& delta_ke) {
        element_div(delta_ke, new_ke, old_ke);
    }

    // 密文更新算法 RISE.Upd
    void UpdCiphertext(element_t& delta_ke, element_t ciphertext[], element_t updated_ciphertext[], element_t& new_y) {
        element_t C1, C2, r, C1_new, C2_new;
        element_init_G1(C1, pairing);
        element_init_G1(C2, pairing);
        element_init_G1(C1_new, pairing);
        element_init_G1(C2_new, pairing);
        element_init_Zr(r, pairing);

        element_set(C1, ciphertext[0]);
        element_set(C2, ciphertext[1]);

        // 随机选择新的 r
        element_random(r);

        // 计算新的 C1 
        element_t tmp1, tmp2;
        element_init_G1(tmp1, pairing);
        element_init_G1(tmp2, pairing);
        element_pow_zn(tmp1, C1, delta_ke);
        element_pow_zn(tmp2, new_y, r);
        element_mul(C1_new, tmp1, tmp2);

        // 计算新的 C2 = g^r * C2
        element_pow_zn(C2_new, g, r);
        element_mul(C2_new, C2_new, C2);

        // 将更新后的密文存储到 updated_ciphertext 中
        element_set(updated_ciphertext[0], C1_new);
        element_set(updated_ciphertext[1], C2_new);

        // 释放临时变量
        element_clear(C1);
        element_clear(C2);
        element_clear(r);
        element_clear(C1_new);
        element_clear(C2_new);
    }
};


// int main() {
//     RISE rise;

//     // 初始化加密密钥
//     element_t key;
//     element_init_Zr(key, rise.GetPairing());
//     element_random(key); // 随机生成密钥
//     rise.SetKey(key);

//     // 生成10个文件
//     std::string input_folder = "./Repository/R3";
//     std::string encrypted_folder = "./Repository/R3/encrypted";
//     std::string decrypted_folder = "./Repository/R3/decrypted";

//     // 创建文件夹
//     fs::create_directories(input_folder);
//     fs::create_directories(encrypted_folder);
//     fs::create_directories(decrypted_folder);

//     // 生成10个文件
//     generate_files(input_folder, 10, 1024, rise); // 每个文件1KB

//     // 加密文件夹中的所有文件
//     encrypt_folder(input_folder, encrypted_folder, rise);

//     // 解密文件夹中的所有文件
//     decrypt_folder(encrypted_folder, decrypted_folder, rise);

//     // 释放资源
//     element_clear(key);

//     return 0;
// }