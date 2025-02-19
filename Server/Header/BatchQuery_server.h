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

#define PORT 443

using namespace std;

// Server test function for the registration protocol
void server_batchquery_test() {
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
    
        string set_size_str = receive_string(client_socket);
        int set_size = stoi(set_size_str);

        string index_str[set_size];
        for (int i = 0; i < set_size; i++)
        {
            index_str[i] = receive_string(client_socket);
        }

        JsonFileHandler handler("../Key/hue_key.json");
        string rho = "7f267d783663";
        nlohmann::json result = handler.readByRho(rho);
        string encoded_c_hue = result["updatable_encryption_key"];
        vector<unsigned char> c_hue_vec = base64_decode(encoded_c_hue);
        string encoded_tag = result["tag"];
        vector<unsigned char> tag_vec = base64_decode(encoded_tag);    
        
        send_binary(client_socket, c_hue_vec);
        send_binary(client_socket, tag_vec);

        for (int i = 0; i < set_size; i++)
        {
            string file_path = string("../File/R1/Receive/file")+index_str[i]+"_cipher.dat";
            send_file(client_socket, file_path);
        }

        for (int i = 0; i < set_size; i++)
        {
            string meta_path = string("../File/Meta/Receive/meta")+index_str[i]+"_cipher.dat";
            send_file(client_socket, meta_path);
        }

        RISE rise;
        int array_size = 2;
        element_t agg_cipher1, agg_cipher2;
        element_init_G1(agg_cipher1, rise.GetPairing());
        element_init_G1(agg_cipher2, rise.GetPairing()); 
        element_set1(agg_cipher1);  
        element_set1(agg_cipher2);      
        cout << "In the loop" << endl;
        for (int i = 0; i < set_size; i++)
        {
            element_t proof_cipher[array_size];
            for (int j = 0; j < array_size; j++)
            {   
                element_init_G1(proof_cipher[j], rise.GetPairing());
            }
            string proof_path = string("../File/Proof/Receive/proof")+index_str[i]+"_cipher.dat";
            load_G1elementVec_from_file(proof_path, proof_cipher, array_size, rise.GetPairing());
            cout << "i= " << i << endl;
            element_mul(agg_cipher1, agg_cipher1, proof_cipher[0]);
            element_mul(agg_cipher2, agg_cipher2, proof_cipher[1]);
            cout << "i2= " << i << endl;
            for (int j = 0; j < array_size; j++)
            {   
                element_clear(proof_cipher[j]);
            }
        }
        cout << "In the loop" << endl;
        element_printf("The agg1 is %B\n", agg_cipher1);
        element_printf("The agg2 is %B\n", agg_cipher2);
        send_element(client_socket, agg_cipher1);
        send_element(client_socket, agg_cipher2);

        element_clear(agg_cipher1);
        element_clear(agg_cipher2);
    } catch (const std::exception& ex) {
        std::cerr << "Error during server processing: " << ex.what() << std::endl;
    }

    // Close connection
    close(client_socket);
    close(server_socket);
    std::cout << "Server test completed." << std::endl;
}