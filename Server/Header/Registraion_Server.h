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
void server_registraion_test() {
    std::cout << "Starting server test for the registration protocol..." << std::endl;

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
        // Initialize NIZK
        NIZKProof nizk;

        // Receive alpha
        string alpha_str = receive_string(client_socket);
        cout << "Alpha received from the client: " << alpha_str << std::endl;
        
        EC_POINT* alpha = EC_POINT_new(nizk.getGroup());
        alpha = EC_POINT_hex2point(nizk.getGroup(), alpha_str.c_str(), NULL, nizk.getCtx());
        
        if (EC_POINT_is_on_curve(nizk.getGroup(), alpha, nizk.getCtx()) != 1) {
            std::cerr << "The point is not on the curve!" << std::endl;
            return;
        }

        // Generate random beta and proof
        nizk.setAlpha(alpha);
        nizk.setBeta(alpha);

        // Generate NIZK proof
        auto pi_o = nizk.generateProof();

        // Send beta and proof to the client
        char* beta_str = EC_POINT_point2hex(nizk.getGroup(), nizk.getBeta(), POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx());
        send_string(client_socket, beta_str);
        cout << "Sent beta to the client: " << beta_str << endl;

        send_string(client_socket, pi_o.first);
        send_string(client_socket, BN_bn2hex(pi_o.second));
        cout << "Sent NIZK proof to the client: " << pi_o.first << " " << BN_bn2hex(pi_o.second) << endl;

        // Receive additional registration data
        cout << "the beginning of the receive" << endl;
        string rho = receive_string(client_socket);
        string pk_c_str = receive_string(client_socket);
        cout << "the begin of binary" << endl;
        vector<unsigned char> received_c_kek = receive_binary(client_socket);
        vector<unsigned char> received_tag = receive_binary(client_socket);

        // cout << "rho: " << rho << endl;
        // cout << "pk_c_str: " << pk_c_str << endl;
        // // cout << "c_kek: " << c_kek << endl;
        // // cout << "tag: " << tag << endl;

        string encoded_c_kek = base64_encode(received_c_kek);
        string encoded_tag = base64_encode(received_tag);

        cout << "after encode" << endl;
        // Store user data in JSON file
        JsonFileHandler handler("../Storage/userList.json");

        // 组织 JSON 数据
        nlohmann::json dataToWrite;
        dataToWrite[rho] = {
            {"public_key", pk_c_str}, 
            {"key_encryption_key", encoded_c_kek}, 
            {"tag", encoded_tag}
        };

        // 写入 JSON
        handler.write(dataToWrite);

        // Clean up resources
        EC_POINT_free(alpha);
    } catch (const std::exception& ex) {
        std::cerr << "Error during server processing: " << ex.what() << std::endl;
    }

    // Close connection
    close(client_socket);
    close(server_socket);
    std::cout << "Server test completed." << std::endl;
}