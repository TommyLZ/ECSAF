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

void client_key_update()
{
    std::cout << "Starting client test for the FileUpdate protocol..." << std::endl;

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
        HVC hvc(n);
        string label_file_path = "../File/Label/label.dat";
        element_t C, r;
        element_init_G1(C, hvc.getPairing());
        element_init_Zr(r, hvc.getPairing());
        load_label_from_file(label_file_path, hvc.getPairing(), C, r);

        element_t zero_vec[n], zero_C;
        element_init_Zr(zero_C, hvc.getPairing());
        for (int i = 0; i < n; i++)
        {
            element_init_G1(zero_vec[i], hvc.getPairing());
        }
        element_init_G1(C, hvc.getPairing());
        hvc.commit(zero_vec, n, C, r);

        element_t C_out;
        element_init_G1(C_out, hvc.getPairing());     
        hvc.comHom(C, zero_C, C_out);   
        string new_label_file_path =  "../File/Label/Keylabel.dat";
        save_label_to_file(new_label_file_path, C_out, r);

        cout << "1" << endl;
        RISE rise;
        cout << "2" << endl;
        element_t new_k_hue;
        element_init_Zr(new_k_hue, rise.GetPairing());
        element_random(new_k_hue);
        rise.SetKey(new_k_hue);

        cout << "after new key" << endl;
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

        cout << "The first place" << endl;
        element_t old_k_hue;
        element_init_Zr(old_k_hue, rise.GetPairing());
        element_from_bytes(old_k_hue, k_hue_byte);

        cout << "The second place" << endl;
        element_t delta_key;
        element_init_Zr(delta_key, rise.GetPairing());
        rise.NextKey(new_k_hue, old_k_hue, delta_key);

        cout << "The third place" << endl;
        element_t e_j;
        element_init_G1(e_j, rise.GetPairing());
        element_pow_zn(e_j, rise.GetGenerator(), new_k_hue);

        send_element(client_socket, delta_key);
        send_element(client_socket, e_j);
        send_element(client_socket, r);
      
    }
    catch (const exception &ex)
    {
        std::cerr << "Error during client processing: " << ex.what() << std::endl;
    }

    close(client_socket);
    std::cout << "KeyUpdate protocol completed successfully!" << std::endl;
}