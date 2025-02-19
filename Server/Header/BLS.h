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
    element_t g;            // Generator of G2
    element_t public_key;   // Public key (in G2)
    element_t secret_key;   // Secret key (in Zr)

    const std::string secret_key_path = "../Key/secret_signing_key.dat";
    const std::string public_key_path = "../Key/public_signing_key.dat";
    const std::string g_file_path = "../Key/g.dat"; // Path to store g

public:
    // Constructor: Initialize pairing and elements
    BLS() {
        const std::string param_file = "../Param/a.param";

        // Load pairing parameters from file
        char param[1024];
        std::ifstream file(param_file, ios::binary);
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
            element_printf("****************The initializatin of g is %B\n", g);
        } else {
            element_random(g);
            save_gen_to_file(g_file_path, g);
        }

        // Initialize keys
        initialize_keys();
    }

    // Destructor: Clear pairing and elements
    ~BLS() {
        element_clear(g);
        element_clear(public_key);
        element_clear(secret_key);
        pairing_clear(pairing);
    }

    // Initialize keys: Generate and store if not exist, otherwise load from file
    void initialize_keys() {
        if (filesystem::exists(secret_key_path) && filesystem::exists(public_key_path)) {
            // Keys exist, load them
            cout << "^^^^^The key exists" << endl;
            load_key_from_file(secret_key_path, secret_key, pairing);
            element_printf("The key after load %B\n", secret_key);
            load_key_from_file(public_key_path, public_key, pairing);
        } else {
            // Keys do not exist, generate and save them
            cout << "generate keys" << endl;
            generate_and_store_keys();
        }
    }

    // Generate keys and store them in files
    void generate_and_store_keys() {
        element_random(g);

        // Generate secret key
        element_random(secret_key);
         element_printf("the secret key is %B\n", secret_key);

        // Compute public key: public_key = g^secret_key
        element_pow_zn(public_key, g, secret_key);
        element_printf("the public key is %B\n", public_key);

        // Save keys to files
        save_key_to_file(secret_key_path, secret_key);
        save_key_to_file(public_key_path, public_key);
    }

    // Get the public key as a string
    std::string get_public_key_as_string() {
        char buffer[1024];
        element_snprint(buffer, sizeof(buffer), public_key);
        return std::string(buffer);
    }

    void set_public_key_from_string(const string& public_key_str) {
        try {
            // 将字符串转换为 element_t 类型
            if (element_set_str(public_key, public_key_str.c_str(), 10) < 0) { // 10 表示字符串的基数（十进制）
                throw std::runtime_error("Failed to convert string to element_t.");
            }

            element_printf("The public key set from string is %B\n", public_key);

            // 打印调试信息
            std::cout << "Successfully converted string back to element_t." << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << std::endl;
            throw; // 重新抛出异常
        }
    }


    // Sign a message (hash should be precomputed)
    std::string sign(const std::string& hash) {
        element_t h, sig;
        element_init_G1(h, pairing);
        element_init_G1(sig, pairing);

        element_printf("^^^^^^^^^^^The secret key is %B\n", secret_key);
        element_from_hash(h, (void*)hash.c_str(), hash.size()); // Map hash to G1
        element_pow_zn(sig, h, secret_key);                    // sig = h^secret_key

        char buffer[1024];
        element_snprint(buffer, sizeof(buffer), sig);

        element_clear(h);
        element_clear(sig);

        element_printf("The public key is %B\n", public_key);
        cout << "The hash is " << hash << endl;
        cout << "The signature is " << string(buffer) << endl;
        element_printf("The generator is %B\n", g); 
        
        return std::string(buffer);
    }

    // Verify a signature
    bool verify(const std::string& hash, const std::string& signature) {
        element_t h, sig, temp1, temp2;
        element_init_G1(h, pairing);
        element_init_G1(sig, pairing);
        element_init_GT(temp1, pairing);
        element_init_GT(temp2, pairing);

        // element_from_hash(h, (void*)hash.c_str(), hash.size()); // Map hash to G1
        // element_set_str(sig, signature.c_str(), 10);           // Load signature from string

        pairing_apply(temp1, sig, g, pairing);        // temp1 = e(sig, g)
        element_printf("The g in verify is %B\n", g);
        pairing_apply(temp2, h, public_key, pairing); // temp2 = e(h, public_key)

        bool result = (element_cmp(temp1, temp2) == 0);

        element_clear(h);
        element_clear(sig);
        element_clear(temp1);
        element_clear(temp2);

        return result;
    }
};