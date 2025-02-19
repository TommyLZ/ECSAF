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

void client_query_test()
{
    std::cout << "Starting client test for the query protocol..." << std::endl;

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
        int index = 5;
        send_string(client_socket, to_string(index));

        vector<unsigned char> c_hue_vec = receive_binary(client_socket);
        vector<unsigned char> c_hue_tag_vec = receive_binary(client_socket);

        string receive_file_path = "../File/R1/Receive/Single";
        receive_file(client_socket, receive_file_path);

        string receive_meta_path = "../File/Meta/Receive/Single";
        receive_file(client_socket, receive_meta_path);

        string receive_proof_path = "../File/Proof/Receive/Single";
        receive_file(client_socket, receive_proof_path);

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

        RISE rise;
        element_t k_hue;
        element_init_Zr(k_hue, rise.GetPairing());
        element_from_bytes(k_hue, k_hue_byte);
        element_printf("The secret key hue is %B\n", k_hue);
        rise.SetKey(k_hue);

        string encrypted_file_path = receive_file_path + "/file" + to_string(index) + "_cipher.dat";
        string decrypted_file_path = string("../File/R1/Recover/Single/") + "file" + to_string(index) + "_plain.dat"; // Decrypt File
        decrypt_file(encrypted_file_path, decrypted_file_path, rise);

        // string full_encrypted_meta_path = receive_proof_path + "/proof" + to_string(index) + "_cipher.dat";
        // string decrypted_meta_path = string("../File/Proof/Recover/Single/proof") + to_string(index) + "_plain.dat"; // Decrypt membership proof
        // decrypt_file(full_encrypted_meta_path, decrypted_meta_path, rise);

        PedersenCommitment PC;
        int array_size = 2;
        element_t commit_cipher[array_size];
        // element_t random_cipher[array_size];
        for (int i = 0; i < array_size; i++)
        {
            element_init_G1(commit_cipher[i], rise.GetPairing());
            // element_init_G1(random_cipher[i], rise.GetPairing());
        }
        element_t r;
        element_init_Zr(r, PC.getPairing());
        string meta_cipher_filename = receive_meta_path + "/meta" + to_string(index) + "_cipher.dat";
        read_elements_from_file(meta_cipher_filename, commit_cipher, r, rise.GetPairing());

        element_t c;
        element_init_G1(c, PC.getPairing());
        // element_init_Zr(r, PC.getPairing());
        rise.DecryptElement(commit_cipher, c);
        // rise.DecryptElement(random_cipher, r);

        element_t hash, out;
        element_init_G1(hash, PC.getPairing());
        element_init_Zr(out, PC.getPairing());
        hash_file_to_element(decrypted_file_path, hash); // Generate a hash digest for each file
        convert_G1_to_Zr(out, hash, PC.getPairing());

        if (PC.verify(out, r, c))
        {
            cout << "PC commitment verification succeeds!" << endl;
        }
        else
        {
            cout << "PC commitment verification fails!" << endl;
        }

        int n = 10;
        HVC hvc(n);
        element_t C,hvc_r;
        element_init_G1(C, hvc.GetPairing());
        element_init_Zr(hvc_r, hvc.GetPairing());
        cout << "&&&1" << endl;
        string lable_path = "../File/Label/label.dat";
        load_label_from_file(lable_path, hvc.GetPairing(), C, hvc_r);

        cout << "hello" << endl; 
        element_t proof;
        element_init_G1(proof, hvc.GetPairing());
        string full_encrypted_proof_path = receive_proof_path + "/proof" + to_string(index) + "_cipher.dat";
        element_t proof_cipher[array_size];
        for (int i = 0; i < 2; i++)
        {
            element_init_G1(proof_cipher[i], rise.GetPairing());
        }
        cout << "before load" << endl;
        load_G1elementVec_from_file(full_encrypted_proof_path, proof_cipher, array_size, rise.GetPairing());
        for (int i = 0; i < 2; i++)
        {
            element_printf("The ciphertext of the proof is %B\n", proof_cipher[i]);
        }
        rise.DecryptElement(proof_cipher, proof);

        cout << "read, finish" << endl;
        if (hvc.verify(C, c, proof, index))
        {
            cout << "Vc commitment verification succeeds!" << endl;
        }
        else
        {
            cout << "VC commitment verification fails!" << endl;
        }
        
    }
    catch (const exception &ex)
    {
        std::cerr << "Error during client processing: " << ex.what() << std::endl;
    }

    close(client_socket);
    std::cout << "Query protocol completed successfully!" << std::endl;
}