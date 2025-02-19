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
void server_query_test() {
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

    } catch (const std::exception& ex) {
        std::cerr << "Error during server processing: " << ex.what() << std::endl;
    }

    // Close connection
    close(client_socket);
    close(server_socket);
    std::cout << "Server test completed." << std::endl;
}