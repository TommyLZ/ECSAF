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
void server_share() {
    std::cout << "Starting server test for the share protocol..." << std::endl;

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

        vector<unsigned char> new_received_c_hue = receive_binary(client_socket);
        vector<unsigned char> new_received_c_hue_tag = receive_binary(client_socket);

        //Store
        string new_encoded_c_hue = base64_encode(new_received_c_hue);
        string new_encoded_c_hue_tag = base64_encode(new_received_c_hue_tag);

        // cout << "after encode" << endl;
        // Store user data in JSON file
        JsonFileHandler new_handler("../Key/new_client_hue_key.json");

        // 组织 JSON 数据
        nlohmann::json dataToWrite;
        string rho_new = "746472683663";
        dataToWrite[rho_new] = {
                {"updatable_encryption_key", new_encoded_c_hue}, 
                {"tag", new_encoded_c_hue_tag}
        };

        // 写入 JSON
        new_handler.write(dataToWrite);
    } catch (const std::exception& ex) {
        std::cerr << "Error during server processing: " << ex.what() << std::endl;
    }

    // Close connection
    close(client_socket);
    close(server_socket);
    std::cout << "Server test completed." << std::endl;
}