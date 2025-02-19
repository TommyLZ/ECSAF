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
#include "AugUpdate.h"

#define PORT 443

using namespace std;

// Server test function for the registration protocol
void server_key_update() {
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
        JsonFileHandler handler("../Key/hue_key.json");
        string rho = "7f267d783663";
        nlohmann::json result = handler.readByRho(rho);
        string encoded_c_hue = result["updatable_encryption_key"];
        vector<unsigned char> c_hue_vec = base64_decode(encoded_c_hue);
        string encoded_tag = result["tag"];
        vector<unsigned char> tag_vec = base64_decode(encoded_tag);    // vector<unsigned char> received_c_hue = receive_binary(client_socket);
        
        send_binary(client_socket, c_hue_vec);
        send_binary(client_socket, tag_vec);

        RISE rise;
        element_t delta_key;
        element_init_Zr(delta_key, rise.GetPairing());

        element_t e_j;
        element_init_G1(e_j, rise.GetPairing());

        element_t r;
        element_init_G1(r, rise.GetPairing());       

        receive_element(client_socket, delta_key);
        receive_element(client_socket, e_j);
        receive_element(client_socket, r);

        cout << "before loop" << endl;
        
        int array_size = 2;
        int n = 10;
        for (int i = 0; i < n; i++)
        {  
            cout << "The order " << i << endl;
            // Update the file
            string old_file_cipher_path = string("../File/R1/Receive/file") + to_string(i) + "_cipher.dat";
            cout << "The order " << i << endl;
            load_file_update(old_file_cipher_path, old_file_cipher_path, rise, delta_key, e_j);
            cout << "The **order " << i << endl;

            // Update the proof
            element_t old_proof_cipher[array_size];
            element_t new_proof_cipher[array_size];
            for (int j = 0; j < array_size; j++)
            {
                element_init_G1(old_proof_cipher[j], rise.GetPairing());
                element_init_G1(new_proof_cipher[j], rise.GetPairing());
            }

            string old_proof_cipher_path = string("../File/Proof/Receive/proof") + to_string
            (i) + "_cipher.dat";
            cout << "This1" << endl;
            load_G1elementVec_from_file(old_proof_cipher_path, old_proof_cipher, array_size, rise.GetPairing());
            cout << "This2" << endl;
            rise.UpdCiphertext(delta_key, new_proof_cipher, old_proof_cipher, e_j);
            cout << "This3" << endl;
            save_G1elementVec_to_file(old_proof_cipher_path, new_proof_cipher, array_size);
            cout << "That" << endl;

            for (int j = 0; j < array_size; j++)
            {
                element_clear(old_proof_cipher[j]);
                element_clear(new_proof_cipher[j]);
            }
        }

        cout << " the second loop" << endl;

        HVC hvc(n);
        element_t zero_vec[n];
        for (int i = 0; i < n; i++)
        {
            element_init_G1(zero_vec[i], hvc.getPairing());
            element_set0(zero_vec[i]);
        }
        element_t pi[n];
        cout << "before loading" << endl;
        for (int i = 0; i < n; i++)
        {
            element_init_G1(pi[i], hvc.getPairing());
            hvc.open(zero_vec, n, i, r, pi[i]);

            element_t gamma_i;
            element_init_Zr(gamma_i, rise.GetPairing());
            element_random(gamma_i);

            element_t zero_proof_cipher[array_size];
            element_t old_proof_cipher[array_size];
            for (int j=0; j < array_size; j++)
            {
                element_init_G1(zero_proof_cipher[j], rise.GetPairing());
                element_init_G1(old_proof_cipher[j], rise.GetPairing());
            }

            element_pow_zn(zero_proof_cipher[0], e_j, gamma_i);
            
            element_t tmp;
            element_init_G1(tmp, rise.GetPairing());
            element_pow_zn(tmp, rise.GetGenerator(), gamma_i);
            element_mul(zero_proof_cipher[1], tmp, pi[i]);

            string old_proof_cipher_path = string("../File/Proof/Receive/proof") + to_string
            (i) + "_cipher.dat";
            cout << "before loading" << endl;
            load_G1elementVec_from_file(old_proof_cipher_path, old_proof_cipher, array_size, rise.GetPairing());
           
            cout << "after loading" << endl;
            element_mul(zero_proof_cipher[0], zero_proof_cipher[0], old_proof_cipher[0]);
            element_mul(zero_proof_cipher[1], zero_proof_cipher[1], old_proof_cipher[1]);

            cout << "after after loading" << endl;
            save_G1elementVec_to_file(old_proof_cipher_path, zero_proof_cipher, array_size);
            cout << "after after after loading" << endl;
        
            element_clear(gamma_i);
            element_clear(tmp);
            for (int j=0; j < array_size; j++)
            {
                element_clear(zero_proof_cipher[j]);
                element_clear(old_proof_cipher[j]);
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