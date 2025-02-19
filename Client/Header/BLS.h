#pragma once

#include <pbc/pbc.h>
#include <string>
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <filesystem>
#include "IOUtils.h"

class BLS {
private:
    pairing_t pairing;
    element_t g; // Generator of G2
    element_t public_key; // Public key (in G2)
    element_t secret_key; // Secret key (in Zr)
    const string g_file_path = "../Key/g.dat"; // Path to store g

public:
    // Constructor: Initialize pairing and elements
    BLS() {
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

        // Initialize elements
        element_init_G2(g, pairing);
        element_init_G2(public_key, pairing);
        element_init_Zr(secret_key, pairing);

        // Load or generate g
        if (filesystem::exists(g_file_path)) {
            load_gen_from_file(g_file_path, g);
            element_printf("********The initialization of g is %B\n", g);
        } else {
            element_random(g);
            save_gen_to_file(g_file_path, g);
        }

        // Check if keys already exist
        if (filesystem::exists("../Key/server_public_signing_key.dat")){
            cout << "&&&&&&&Did reload public key" << endl;
            load_key_from_file("../Key/server_public_signing_key.dat", public_key, pairing);
            element_printf("The public key after load is %B\n", public_key);
        }
    }

    // Destructor: Clear pairing and elements
    ~BLS() {
        element_clear(g);
        element_clear(public_key);
        element_clear(secret_key);
        pairing_clear(pairing);
    }

    // Getters and Setters for g
    void set_g(element_t& new_g) {
        element_set(g, new_g);
    }

    void get_g(element_t& out_g) {
        element_set(out_g, g);
    }

    // Getters and Setters for public_key
    void set_public_key() {
        element_printf("the public key is: %B\n", secret_key);
        element_pow_zn(public_key, g, secret_key);
        element_printf("the public key is: %B\n", public_key);
        save_key_to_file("../Key/public_signing_key.dat", public_key);
    }

    void get_public_key(element_t& out_public_key) {
        element_init_G2(out_public_key, pairing);
        element_pow_zn(public_key, g, secret_key);
        element_set(out_public_key, public_key);
    }

    // Getters and Setters for secret_key
    void set_secret_key(string& secret_key_str) {
        // element_t new_secret_key;
        // element_init_Zr(new_secret_key, pairing);
        cout << "secret_key_str: " << secret_key_str << endl;
        element_set_str(secret_key, secret_key_str.c_str(), 16);
        // element_set(secret_key, new_secret_key);
        element_printf("the secret signing key is: %B\n", secret_key);
    }

    void get_secret_key(element_t& out_secret_key) {
        element_init_Zr(out_secret_key, pairing);
        element_set(out_secret_key, secret_key);
    }

    // Get the public key as a string
    std::string get_public_key_as_string() {
        char buffer[1024];
        element_printf("the public key is in the string: %d\n", public_key);
        element_snprint(buffer, sizeof(buffer), public_key);
        cout << "The buffer is: " << string(buffer) << endl;
        return string(buffer);
    }

    void set_public_key_from_string(const std::string& public_key_str, element_t& public_key, pairing_t pairing) {
        try {
            // 将字符串转换为 element_t 类型
            if (element_set_str(public_key, public_key_str.c_str(), 10) < 0) { // 10 表示字符串的基数（十进制）
                throw std::runtime_error("Failed to convert string to element_t.");
            }

            // 打印调试信息
            std::cout << "Successfully converted string back to element_t." << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << std::endl;
            throw; // 重新抛出异常
        }
    }

    // Sign a message (hash should be precomputed)
    string sign(const std::string& hash) {
        element_t h, sig;
        element_init_G1(h, pairing);
        element_init_G1(sig, pairing);

        element_printf("The g in verify is %B\n", g);
        element_from_hash(h, (void* )hash.c_str(), hash.size()); // Map hash to G1
        element_pow_zn(sig, h, secret_key); // sig = h^secret_key

        char buffer[1024];
        element_snprint(buffer, sizeof(buffer), sig);

        element_clear(h);
        element_clear(sig);
        return std::string(buffer);
    }

    // Verify a signature
    bool verify(const std::string& hash, const std::string& signature) {
        element_t h, sig, temp1, temp2;
        element_init_G1(h, pairing);
        element_init_G1(sig, pairing);
        element_init_GT(temp1, pairing);
        element_init_GT(temp2, pairing);


        element_printf("The public key is %B\n", public_key);
        cout << "The hash is " << hash << endl;
        cout << "The signature is " << signature << endl;
        element_printf("The generator is %B\n", g);       

        pairing_apply(temp1, sig, g, pairing); // temp1 = e(sig, g)
        element_printf("The temp1 is %B\n", temp1);  
        pairing_apply(temp2, h, public_key, pairing); // temp2 = e(h, public_key)
        element_printf("The temp2 is %B\n", temp2); 

        bool result = (element_cmp(temp1, temp2) == 0);

        element_clear(h);
        element_clear(sig);
        element_clear(temp1);
        element_clear(temp2);

        return result;
    }
};

// // Example usage
// int main() {
//     try {
//         BLS bls;

//         // Generate keys if not already present
//         bls.generate_keys();
//         std::cout << "Public Key: " << bls.get_public_key_as_string() << std::endl;

//         // Message hash (example: precomputed hash "ABCDEF")
//         std::string message_hash = "ABCDEF";

//         // Sign the message
//         std::string signature = bls.sign(message_hash);
//         std::cout << "Signature: " << signature << std::endl;

//         // Verify the signature
//         bool is_valid = bls.verify(message_hash, signature);
//         std::cout << (is_valid ? "Signature is valid" : "Signature is invalid") << std::endl;
//     } catch (const std::exception& e) {
//         std::cerr << "Error: " << e.what() << std::endl;
//     }

//     return 0;
// }