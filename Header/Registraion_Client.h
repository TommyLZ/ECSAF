#pragma once
#include <iostream>
#include <cstring>
#include <pbc/pbc.h>
#include "NIZK.h"
#include "Network_Utils.h"
#include "Argon2i.h"
#include "ECGroupHasher.h"
#include "SHA.h"
#include "BLS.h"
#include "RandomHex.h"
#include "AES_GCM.h"

using namespace std;

#define PORT 443
#define SERVER_PUBLIC_IP "8.141.95.140"

void client_registration_test(const string& identity, const string& password) {
    std::cout << "Starting client test for the registration protocol..." << std::endl;

    // Initialize client socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT); // Server port
    
    if (inet_pton(AF_INET, SERVER_PUBLIC_IP, &server_addr.sin_addr) <= 0) { // Server IP address
        std::cerr << "Invalid address or address not supported!" << std::endl;
        return;
    } 

    // Connect to the server
    if (connect(client_socket, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to connect to the server!" << std::endl;
        return;
    }
    std::cout << "Connected to the server." << std::endl;

    try {
        // Step 1: Initialize NIZK
        NIZKProof nizk;

        // Step 2: Generate random alpha
        BIGNUM* r = BN_new();
        do {
            BN_rand_range(r, nizk.getOrder()); // Generate random scalar r such that 0 <= r < order
        } while (BN_is_zero(r));

        Argon2iHasher argon2i;
        string argon2i_input = identity + password;
        string hashedValue = argon2i.hashPassword(argon2i_input);

        // Convert hash to an elliptic curve group element
        EC_POINT* hashToGroup = ECGroupHasher::hashToGroupElement(hashedValue, nizk.getGroup(), nizk.getCtx(), nizk.getOrder());

        // Blind the hash
        EC_POINT* alpha = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), alpha, NULL, hashToGroup, r, nizk.getCtx());
        nizk.setAlpha(alpha);

        // Step 3: Send alpha to the server
        send_string(client_socket, EC_POINT_point2hex(nizk.getGroup(), alpha, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx()));
        // cout << "Alpha sent to the server: " << EC_POINT_point2hex(nizk.getGroup(), alpha, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx()) << endl;

        // Step 4: Receive beta and NIZK proof
        string beta_str = receive_string(client_socket);
        string pi_o_first = receive_string(client_socket);
        string pi_o_second_str = receive_string(client_socket);

        nizk.setBeta(beta_str);
        // cout << "Beta received from the server: " << beta_str << endl;

        BIGNUM* pi_o_second = BN_new();
        BN_hex2bn(&pi_o_second, pi_o_second_str.c_str());
        // cout << "NIZK proof received from the server: " << pi_o_first << " " << pi_o_second_str << endl;

        // Step 5: Verify NIZK proof
        if (nizk.verifyProof(pi_o_first, pi_o_second)) {
            std::cout << "NIZK verification succeeded!" << std::endl;
        } else {
            std::cerr << "NIZK verification failed. Aborting test." << std::endl;
            BN_free(pi_o_second);
            EC_POINT_free(alpha);
            EC_POINT_free(hashToGroup);
            return;
        }

        // Step 6: Compute the unblinded value
        BIGNUM* rInverse = BN_new();
        BN_mod_inverse(rInverse, r, nizk.getOrder(), nizk.getCtx());
        
        EC_POINT* unblind = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), unblind, NULL, NULL, rInverse, nizk.getCtx());
        
        string hs = hashSHA256({password, EC_POINT_point2hex(nizk.getGroup(), unblind, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx())});
        string rho = hashSHA256({identity, hs}).substr(0, identity.size());
        string sk_c_str = hashSHA256({"Sign", hs}).substr(0, 20);

        // Step 7: Setup BLS signature
        BLS bls;
        bls.set_secret_key(sk_c_str);
        bls.set_public_key();

        // Step 8: Setup AES-GCM encryption
        vector<unsigned char> k_ae = hashSHA256_key({"AE", hs});
        vector<unsigned char> k_kek_bytes = generateHex64();

        AESGCM aes_GCM;
        aes_GCM.set_key(k_ae);

        unsigned char c_kek[k_kek_bytes.size()];
        unsigned char tag[AESGCM::get_tag_size()];
        aes_GCM.encrypt(k_kek_bytes.data(), k_kek_bytes.size(), c_kek, tag);

        // Step 9: Send encrypted data to the server
        vector<unsigned char> c_kek_vec(c_kek, c_kek + sizeof(c_kek));
        vector<unsigned char> tag_vec(tag, tag + AESGCM::get_tag_size());
        send_string(client_socket, rho);
        send_string(client_socket, bls.get_public_key_as_string());
        send_binary(client_socket, c_kek_vec);
        send_binary(client_socket, tag_vec);
        // send_string(client_socket, base64_encode(reinterpret_cast<const char*>(c_kek), sizeof(c_kek)));
        // send_string(client_socket, base64_encode(reinterpret_cast<const char*>(tag), sizeof(tag)));

        // Cleanup resources
        BN_free(r);
        BN_free(rInverse);
        BN_free(pi_o_second);
        EC_POINT_free(alpha);
        EC_POINT_free(unblind);
        EC_POINT_free(hashToGroup);
    } catch (const exception& ex) {
        std::cerr << "Error during client processing: " << ex.what() << std::endl;
    }

    close(client_socket);
    cout << "Registration protocol completed successfully!" << std::endl;
}