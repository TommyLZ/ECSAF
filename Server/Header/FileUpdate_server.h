#pragma once

#include <iostream>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>
#include <unistd.h>
#include <filesystem>
#include "NIZK.h"
#include "Network_Utils.h"
#include "Argon2i.h"
#include "ECGroupHasher.h"
#include "KeyValueStore.h"
#include "Pedersen.h"
#include "HUE.h"
#include "HVC.h"
#include "IOUtils.h"

#define PORT 443

using namespace std;

// Server test function for the registration protocol
void server_file_update() {
    std::cout << "Starting server test for the query protocol..." << std::endl;

    // Initialize server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        throw std::runtime_error("Failed to create server socket");
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all network interfaces
    server_addr.sin_port = htons(PORT);

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        throw std::runtime_error("Failed to bind server socket");
    }

    if (listen(server_socket, 5) < 0) {
        throw std::runtime_error("Failed to listen on server socket");
    }

    std::cout << "Server is listening on port " << PORT << "..." << std::endl;

    // Accept client connection
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_len);
    if (client_socket < 0) {
        throw std::runtime_error("Failed to accept client connection");
    }
    std::cout << "Client connected." << std::endl;

    try {
        string index_str = receive_string(client_socket);

        JsonFileHandler handler("../Key/hue_key.json");
        string rho = "7f267d783663";
        nlohmann::json result = handler.readByRho(rho);
        string encoded_c_hue = result["updatable_encryption_key"];
        vector<unsigned char> c_hue_vec = base64_decode(encoded_c_hue);
        string encoded_tag = result["tag"];
        vector<unsigned char> tag_vec = base64_decode(encoded_tag);    // vector<unsigned char> received_c_hue = receive_binary(client_socket);
        
        send_binary(client_socket, c_hue_vec);
        send_binary(client_socket, tag_vec);

        string file_path = string("../File/R1/Receive/file")+index_str+"_cipher.dat";
        send_file(client_socket, file_path);

        string meta_path = string("../File/Meta/Receive/meta")+index_str+"_cipher.dat";
        send_file(client_socket, meta_path);

        string proof_path = string("../File/Proof/Receive/proof")+index_str+"_cipher.dat";
        send_file(client_socket, proof_path);

        // Receive the update token
        string update_file_path = string("../File/R1/ReceiveUpdate");
        receive_file(client_socket, update_file_path);

        string update_meta_path = string("../File/Meta/ReceiveUpdate");
        receive_file(client_socket, update_meta_path);

        string n_str = receive_string(client_socket);
        cout << "n_str" << n_str << endl;
        PedersenCommitment PC;
        int n = stoi(n_str);
        element_t increment_vec[n];
        for (int i = 0; i <n; i++)
        {
            element_init_G1(increment_vec[i], PC.getPairing());
            element_set0(increment_vec[i]);
        }
        receive_element(client_socket, increment_vec[stoi(index_str)]);

        int array_size = 2;
        RISE rise;
        element_t e_j;
        element_init_G1(e_j, rise.GetPairing());
        receive_element(client_socket, e_j);

        HVC hvc(n);
        element_t hvc_r, pi[n];
        element_init_Zr(hvc_r, hvc.getPairing());
for (int i = 0; i < n; i++)
{
    element_init_G1(pi[i], hvc.getPairing());
    hvc.open(increment_vec, n, i, hvc_r, pi[i]);

    element_t gamma_i;
    element_init_Zr(gamma_i, rise.GetPairing());
    element_random(gamma_i);

    element_t pi_cipher[array_size];
    for (int i = 0; i < array_size; i++)
    {
        element_init_G1(pi_cipher[i], rise.GetPairing());
    }
    element_pow_zn(pi_cipher[0], e_j, gamma_i);
    
    element_t tmp;
    element_init_G1(tmp, rise.GetPairing());
    element_pow_zn(tmp, rise.GetGenerator(), gamma_i);
    element_mul(pi_cipher[1], tmp, pi[i]);
    
    element_t old_pi_cipher[array_size];
    for (int i = 0; i < array_size; i++)
    {
        element_init_G1(old_pi_cipher[i], rise.GetPairing());
    }
    string old_proof_file_path = string("../File/Proof/Receive/proof") + to_string(i) + "_cipher.dat";
    load_G1elementVec_from_file(old_proof_file_path, old_pi_cipher, array_size, rise.GetPairing());
    element_mul(pi_cipher[0], pi_cipher[0], old_pi_cipher[0]);
    element_mul(pi_cipher[1], pi_cipher[1], old_pi_cipher[1]);
    save_G1elementVec_to_file(old_proof_file_path, pi_cipher, array_size);

    // 释放变量，防止内存泄漏
    element_clear(gamma_i);
    element_clear(tmp);
    element_clear(pi[i]);

    for (int i = 0; i < array_size; i++)
    {
        element_clear(pi_cipher[i]);
        element_clear(old_pi_cipher[i]);
    }
}


    } catch (const std::exception& ex) {
        std::cerr << "Error during server processing: " << ex.what() << std::endl;
    }

    // Close connection
    close(client_socket);
    close(server_socket);
    std::cout << "Server test completed." << std::endl;
}