#pragma once
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <pbc/pbc.h>
#include <vector>
#include <nlohmann/json.hpp>
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
#include "Upload_Client.h"
#include "AugHUE.h"

using namespace std;

#define PORT 443
#define SERVER_PUBLIC_IP "8.141.95.140"

void client_batchquery_test()
{
    std::cout << "Starting client test for the BatchQuery protocol..." << std::endl;

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
        int set_size = 5;
        send_string(client_socket, to_string(set_size));

        int index[set_size] = {0, 1, 2, 6, 9};
        for (int i = 0; i < set_size; i++)
        {
            send_string(client_socket, to_string(index[i]));
        }

        vector<unsigned char> c_hue_vec = receive_binary(client_socket);
        vector<unsigned char> c_hue_tag_vec = receive_binary(client_socket);
        
        string receive_file_path = "../File/R1/Receive/Batch";
        for (int i = 0; i < set_size; i++)
        {
            receive_file(client_socket, receive_file_path);
        }

        string receive_meta_path = "../File/Meta/Receive/Batch";
        for (int i = 0; i < set_size; i++)
        {
            receive_file(client_socket, receive_meta_path);
        }

        RISE rise;
        element_t agg_cipher1, agg_cipher2;
        element_init_G1(agg_cipher1, rise.GetPairing());
        element_init_G1(agg_cipher2, rise.GetPairing()); 
        receive_element(client_socket, agg_cipher1);
        receive_element(client_socket, agg_cipher2);
        element_printf("The agg1 is %B\n", agg_cipher1);
        element_printf("The agg2 is %B\n", agg_cipher2);

       
        string key_path = "../Key/kek_recovered.dat";
        AESGCM aes;
        aes.set_key(key_path);

        // 重新转换回 unsigned char 数组
        unsigned char c_hue[c_hue_vec.size()];
        unsigned char c_hue_tag[AESGCM::get_tag_size()];

        std::memcpy(c_hue, c_hue_vec.data(), c_hue_vec.size());
        std::memcpy(c_hue_tag, c_hue_tag_vec.data(), c_hue_tag_vec.size());

        unsigned char k_hue_byte[sizeof(c_hue)];
        if (!aes.decrypt(c_hue, 32, c_hue_tag, k_hue_byte))
        {
            cout << "Decryption failed!" << endl;
            return;
        }

        element_t k_hue;
        element_init_Zr(k_hue, rise.GetPairing());
        element_from_bytes(k_hue, k_hue_byte);
        element_printf("The secret key hue is %B\n", k_hue);
        rise.SetKey(k_hue);
        
        for (int i = 0; i < set_size; i++)
        {
            string encrypted_file_path = receive_file_path + "/file" + to_string(index[i]) + "_cipher.dat";
            string decrypted_file_path = string("../File/R1/Recover/Batch/") + "file" + to_string(index[i]) + "_plain.dat"; // Decrypt File
            decrypt_file(encrypted_file_path, decrypted_file_path, rise);
        }

        PedersenCommitment PC;
        int array_size = 2;
        element_t commit_cipher[set_size][array_size];
        for (int i = 0; i < set_size; i++)
        {
            for (int j = 0; j < array_size; j++)
            {
                element_init_G1(commit_cipher[i][j], rise.GetPairing());
            }
        }
        element_t r[set_size], c[set_size];
        for (int i = 0; i < set_size; i++)
        {
            element_init_Zr(r[i], PC.getPairing());
            element_init_Zr(c[i], PC.getPairing());
            string meta_cipher_filename = receive_meta_path + "/meta" + to_string(index[i]) + "_cipher.dat";
            read_elements_from_file(meta_cipher_filename, commit_cipher[i], r[i], rise.GetPairing());
            rise.DecryptElement(commit_cipher[i], c[i]);
        }

        for (int i = 0; i < set_size; i++)
        {        
            element_t hash, out;
            element_init_G1(hash, PC.getPairing());
            element_init_Zr(out, PC.getPairing());
            string decrypted_file_path = string("../File/R1/Recover/Batch/") + "file" + to_string(index[i]) + "_plain.dat"; // Decrypt File
            hash_file_to_element(decrypted_file_path, hash); // Generate a hash digest for each file
            convert_G1_to_Zr(out, hash, PC.getPairing());

            if (PC.verify(out, r[i], c[i]))
            {
                cout << i << "th" << "PC commitment verification succeeds!" << endl;
            }
            else
            {
                cout << i << "th" << "PC commitment verification fails!" << endl;
            }
        }

        int n = 10;
        HVC hvc(n);
        element_t C, hvc_r;
        element_init_G1(C, hvc.GetPairing());
        element_init_Zr(hvc_r, hvc.GetPairing());
        cout << "&&&1" << endl;
        string lable_path = "../File/Label/label.dat";
        load_label_from_file(lable_path, hvc.GetPairing(), C, hvc_r);

        element_t aggproof;
        element_init_G1(aggproof, hvc.GetPairing());
        element_t aggproof_cipher[array_size];
        for (int i = 0; i < 2; i++)
        {
            element_init_G1(aggproof_cipher[i], rise.GetPairing());
        }
        element_set(aggproof_cipher[0], agg_cipher1);
        element_set(aggproof_cipher[1], agg_cipher2);
        rise.DecryptElement(aggproof_cipher, aggproof);

        for (int i = 0; i < set_size; i++)
        {
            if (hvc.verify(C, c[i], aggproof, index[i]))
            {
                cout << i << "th" << "Vc commitment verification succeeds!" << endl;
            }
            else
            {
                cout << i << "th" << "VC commitment verification fails!" << endl;
            }
        }
    }
    catch (const exception &ex)
    {
        std::cerr << "Error during client processing: " << ex.what() << std::endl;
    }

    close(client_socket);
    std::cout << "BatchQuery protocol completed successfully!" << std::endl;
}