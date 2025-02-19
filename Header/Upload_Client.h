#pragma once
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <pbc/pbc.h>
#include <vector>
#include <nlohmann/json.hpp>
#include "KeyValueStore.h"
#include "NIZK.h"
#include "Network_Utils.h"
#include "Argon2i.h"
#include "ECGroupHasher.h"
#include "SHA.h"
#include "BLS.h"
#include "RandomHex.h"
#include "AES_GCM.h"
#include "Pedersen.h"
#include "HUE.h"
#include "HVC.h"
#include "AugHUE.h"

using namespace std;

#define PORT 443
#define SERVER_PUBLIC_IP "8.141.95.140"

void client_upload_test()
{
    std::cout << "Starting client test for the upload protocol..." << std::endl;

    // Initialize client socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0)
    {
        std::cerr << "Failed to create socket!" << std::endl;
        return;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT); // Server port

    if (inet_pton(AF_INET, SERVER_PUBLIC_IP, &server_addr.sin_addr) <= 0)
    { // Server IP address
        std::cerr << "Invalid address or address not supported!" << std::endl;
        close(client_socket);
        return;
    }

    // Connect to the server
    if (connect(client_socket, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to connect to the server!" << std::endl;
        close(client_socket);
        return;
    }
    std::cout << "Connected to the server." << std::endl;

    try
    {
        int n = 10;

        RISE rise;
        element_t k_hue;
        element_init_Zr(k_hue, rise.GetPairing());
        element_random(k_hue);
        element_printf("The hue key of upload is %B\n", k_hue);
        rise.SetKey(k_hue); // Set the HUE key

        PedersenCommitment PC;

        string input_folder = "../File/R1/Origin"; // The repository to be upload
        string encrypted_folder = "../File/R1/Send";
        if (!fs::exists(encrypted_folder))
        {
            fs::create_directory(encrypted_folder);
        }

        int count = 0;
        int container_size = n; // 容器大小
        int array_size = 2;     // 每个元素的数组大小

        element_t commitments[n];
        element_t randomness[n];
        for (int i = 0; i < n; ++i)
        {
            element_init_G1(commitments[i], PC.getPairing());
            element_init_Zr(randomness[i], PC.getPairing());
        }
        for (const auto &entry : filesystem::directory_iterator(input_folder))
        {
            if (entry.is_regular_file())
            {
                string input_file = entry.path().string();

                element_t r, c;
                element_t hash, out;
                element_init_G1(hash, PC.getPairing());
                element_init_Zr(out, PC.getPairing());
                hash_file_to_element(input_file, hash);       // Generate a hash digest for each file
                convert_G1_to_Zr(out, hash, PC.getPairing()); // Conver the datatype: hash (G1) --> out: Zr
                PC.commit(out, r, c);                         // Generat commitment for each file hash
                cout << "count: " << count << endl;
                element_printf("out is %B\n", out);
                element_printf("r is %B\n", r);
                element_printf("c is %B\n", c);
                element_set(commitments[count], c); // Store the commitment to an array: commitments
                element_set(randomness[count], r);  // Store the commitment to an array: commitments

                count++;
            }
        }

        // Store Meta to the file
        element_t commit_cipher[container_size][array_size]; // Store the ciphertext of commitment: c
        element_t random_cipher[container_size][array_size]; // Store the ciphertext of randomness: r
        for (int i = 0; i < container_size; i++)
        {
            for (int j = 0; j < 2 * array_size; j++)
            {
                element_init_G1(commit_cipher[i][j], rise.GetPairing());
                element_init_G1(random_cipher[i][j], rise.GetPairing());
            }
        }

        for (int i = 0; i < container_size; i++)
        {
            rise.EncryptElement(commitments[i], commit_cipher[i]); // encrypt the commitment: c

            string filename = "../File/Meta/Send/meta" + to_string(i) + "_cipher.dat";
            write_elements_to_file(filename, commit_cipher[i], randomness[i]);
        }

        // Encrypt files of repository and store the ciphertext
        encrypt_folder(input_folder, encrypted_folder, rise);

        HVC hvc(n);
        element_t C, r;
        hvc.commit(commitments, n, C, r); // Generate the VC commitment for PC commitments

        string lable_path = "../File/Label/label.dat";
        save_label_to_file(lable_path, C, r); // Store the label
        element_t pi;
        element_t c_hat[container_size][array_size]; // The encrypted membership proof array
        for (int i = 0; i < container_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                element_init_G1(c_hat[i][j], hvc.GetPairing());
            }
        }
        for (int i = 0; i < container_size; i++)
        {
            hvc.open(commitments, n, i, r, pi);
            rise.EncryptElement(pi, c_hat[i]);

            for (int j = 0; j < 2; j++)
            {
                element_printf("The ciphertext of the proof is %B\n", c_hat[i][j]);
            }

            string filename = "../File/Proof/Send/proof" + to_string(i) + "_cipher.dat";
            save_G1elementVec_to_file(filename, c_hat[i], array_size);
        }
        cout << "after saving c_hat" << endl;

        // Protect the HUE key using AE key
        string key_path = "../Key/kek_recovered.dat";
        AESGCM aes;
        aes.set_key(key_path);

        unsigned char k_hue_char[32];
        int len = element_to_bytes(k_hue_char, k_hue); // 转换为字节数组
        unsigned char c_hue[32];
        unsigned char c_hue_tag[16]; // AES-GCM 需要的验证标签
        if (!aes.encrypt(k_hue_char, 32, c_hue, c_hue_tag))
        {
            cout << "Encryption failed!" << endl;
            return;
        }

        vector<unsigned char> c_hue_vec(c_hue, c_hue + sizeof(c_hue));
        vector<unsigned char> c_hue_tag_vec(c_hue_tag, c_hue_tag + AESGCM::get_tag_size());
        send_binary(client_socket, c_hue_vec);
        send_binary(client_socket, c_hue_tag_vec);

        string file_path = "../File/R1/Send";
        string meta_path = "../File/Meta/Send";
        string proof_path = "../File/Proof/Send";

        send_folder(client_socket, file_path); // The encrypted file

        send_folder(client_socket, meta_path); // The encrypted meta

        send_folder(client_socket, proof_path); // The encrypted proof

        element_clear(k_hue);
        for (int i = 0; i < n; ++i)
        {
            element_clear(commitments[i]);
            element_clear(randomness[i]);
        }

        for (int i = 0; i < container_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                element_clear(commit_cipher[i][j]);
                element_clear(random_cipher[i][j]);
            }
        }
    }
    catch (const exception &ex)
    {
        std::cerr << "Error during client processing: " << ex.what() << std::endl;
    }

    close(client_socket);
    std::cout << "Upload protocol completed successfully!" << std::endl;
}