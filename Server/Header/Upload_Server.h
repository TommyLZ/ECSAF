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
#include "HUE.h"
#include "AugHUE.h"

#define PORT 443

using namespace std;

// Server test function for the registration protocol
void server_upload_test() {
    std::cout << "Starting server test for the upload protocol..." << std::endl;

    // Initialize server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        throw std::runtime_error("Failed to create server socket");
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all network interfaces
    server_addr.sin_port = htons(PORT);

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
        vector<unsigned char> received_c_hue = receive_binary(client_socket);
        vector<unsigned char> received_c_hue_tag = receive_binary(client_socket);

        //Store
        string encoded_c_hue = base64_encode(received_c_hue);
        string encoded_c_hue_tag = base64_encode(received_c_hue_tag);

        // cout << "after encode" << endl;
        // Store user data in JSON file
        JsonFileHandler handler("../Key/hue_key.json");

        // 组织 JSON 数据
        nlohmann::json dataToWrite;
        string rho = "7f267d783663";
        dataToWrite[rho] = {
                {"updatable_encryption_key", encoded_c_hue}, 
                {"tag", encoded_c_hue_tag}
        };

        // 写入 JSON
        handler.write(dataToWrite);

        string file_path = "../File/R1/Receive";
        receive_file(client_socket, file_path);

        string meta_path = "../File/Meta/Receive";
        receive_file(client_socket, meta_path);

        string proof_path = "../File/Proof/Receive";
        receive_file(client_socket, proof_path);

    } catch (const std::exception& ex) {
        std::cerr << "Error during server processing: " << ex.what() << std::endl;
    }

    // Close connection
    close(client_socket);
    close(server_socket);
    std::cout << "Server test completed." << std::endl;
}