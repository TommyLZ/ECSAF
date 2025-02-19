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
#include "BLS.h"
#include "ECGroupHasher.h"
#include "KeyValueStore.h"

#define PORT 443

using namespace std;

// 服务器端测试函数
void server_login_test() {
    std::cout << "Starting server test for the Login protocol..." << std::endl;

    // 初始化服务器 socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        throw std::runtime_error("Failed to create server socket");
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // 监听所有网络接口
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        throw std::runtime_error("Failed to bind server socket");
    }

    if (listen(server_socket, 5) < 0) {
        throw std::runtime_error("Failed to listen on server socket");
    }

    std::cout << "Server is listening on port " << PORT << "..." << std::endl;

    // 接受客户端连接
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_len);
    if (client_socket < 0) {
        throw std::runtime_error("Failed to accept client connection");
    }
    std::cout << "Client connected." << std::endl;

    try {
        // 初始化 NIZK
        NIZKProof nizk;
        cout << "after nizk initialization" << endl;
        BIGNUM* y = BN_new();
        do{
            BN_rand_range(y, nizk.getOrder());  // Generate random k such that 0 <= k < order
        } while (BN_is_zero(y));
        cout << "spot 1" << endl;
        
        EC_POINT* Y = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), Y, y, NULL, NULL, nizk.getCtx());
        string Y_str = EC_POINT_point2hex(nizk.getGroup(), Y, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx());
        cout << "before bls" << endl;
        BLS bls;
        string sigma_s = bls.sign(Y_str);
        // Verify the signature
        // bool isn_valid1 = bls.verify(Y_str, sigma_s);
        // std::cout << (isn_valid1 ? "Signature is valid" : "Signature is invalid") << std::endl;

        cout << "Send Y to the client: " << Y_str << endl;
        send_string(client_socket, Y_str);
        cout << "Send sigma_s to the client: " << sigma_s << endl;
        send_string(client_socket, sigma_s);

        // 接收 alpha
        string alpha_str = receive_string(client_socket);
        cout << "Alpha received from the server: " << alpha_str << std::endl;
        
        EC_POINT* alpha = EC_POINT_new(nizk.getGroup());
        alpha = EC_POINT_hex2point(nizk.getGroup(), alpha_str.c_str(), NULL, nizk.getCtx());
        
        if (EC_POINT_is_on_curve(nizk.getGroup(), alpha, nizk.getCtx()) != 1) {
            std::cerr << "The point is not on the curve!" << std::endl;
            return ;
        }

        // 生成随机 beta 和证明
        nizk.setAlpha(alpha);
        nizk.setBeta(alpha);

        // 生成 NIZK 证明
        auto pi_o = nizk.generateProof();

        // 发送 beta 和证明给客户端
        char* beta_str = EC_POINT_point2hex(nizk.getGroup(), nizk.getBeta(), POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx());
        send_string(client_socket, beta_str);
        cout << "Send beta to the client: " << beta_str << endl;

        send_string(client_socket, pi_o.first);
        send_string(client_socket, BN_bn2hex(pi_o.second));
        cout << "Send NIZK proof to the client: " << pi_o.first << " " << BN_bn2hex(pi_o.second) << endl;

        string rho = receive_string(client_socket);
        string sigma_c = receive_string(client_socket);
        string X_str = receive_string(client_socket);

        // filesystem::create_directories("../Storage");
        JsonFileHandler handler("../Storage/userList.json");
        nlohmann::json result = handler.readByRho(rho);
        string pk_c_str = result["public_key"];
        string encoded_c_kek = result["key_encryption_key"];
        vector<unsigned char> c_kek_vec = base64_decode(encoded_c_kek);
        string encoded_tag = result["tag"];
        vector<unsigned char> tag_vec = base64_decode(encoded_tag);

        bls.set_public_key_from_string(pk_c_str);

        bool is_valid = bls.verify(X_str + Y_str + sigma_s, sigma_c);
        cout << (is_valid ? "Signature is valid" : "Signature is invalid") << std::endl;

        EC_POINT* X = EC_POINT_new(nizk.getGroup());
        X = EC_POINT_hex2point(nizk.getGroup(), X_str.c_str(), NULL, nizk.getCtx());

        EC_POINT* Xy = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), Xy, NULL, X, y, nizk.getCtx());
        string k_se = hashSHA256({
            sigma_c.c_str(), sigma_s.c_str(), X_str.c_str(), Y_str.c_str(), 
            EC_POINT_point2hex(nizk.getGroup(), Xy, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx())
        });
        cout << "The session key is exchanged!" << endl;
        
        send_binary(client_socket, c_kek_vec);
        send_binary(client_socket, tag_vec);

        // 清理资源
        EC_POINT_free(alpha);
    } catch (const std::exception& ex) {
        std::cerr << "Error during server processing: " << ex.what() << std::endl;
    }

    // 关闭连接
    close(client_socket);
    close(server_socket);
    std::cout << "Server test completed." << std::endl;
}

// // 主函数
// int main() {
//     try {
//         server_test();
//     } catch (const std::exception& ex) {
//         std::cerr << "An error occurred: " << ex.what() << std::endl;
//     }
//     return 0;
// }