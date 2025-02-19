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

void client_share()
{
    std::cout << "Starting client test for the Share protocol..." << std::endl;

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
        vector<unsigned char> c_hue_vec = receive_binary(client_socket);
        vector<unsigned char> c_hue_tag_vec = receive_binary(client_socket);

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

        // Load the new key
        string new_key_path = "../Key/kek_recovered_new.dat";
        aes.set_key(new_key_path);

        unsigned char new_c_hue[32];
        unsigned char new_hue_tag[16]; // AES-GCM 需要的验证标签
        if (!aes.encrypt(k_hue_byte, 32, new_c_hue, new_hue_tag))
        {
            cout << "Encryption failed!" << endl;
            return;
        }

        vector<unsigned char> new_c_hue_vec(new_c_hue, new_c_hue + sizeof(new_c_hue));
        vector<unsigned char> new_hue_tag_vec(new_hue_tag, new_hue_tag + AESGCM::get_tag_size());
        send_binary(client_socket, new_c_hue_vec);
        send_binary(client_socket, new_hue_tag_vec);
    }
    catch (const exception &ex)
    {
        std::cerr << "Error during client processing: " << ex.what() << std::endl;
    }

    close(client_socket);
    std::cout << "Share protocol completed successfully!" << std::endl;
}