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

void client_login_test(const string &identity, const string &password)
{
    std::cout << "Starting client test for the login protocol..." << std::endl;

    // 初始化客户端 socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT); // 服务器端口
    if (inet_pton(AF_INET, SERVER_PUBLIC_IP, &server_addr.sin_addr) <= 0)
    { // 服务器 IP 地址
        std::cerr << "Invalid address or address not supported!" << std::endl;
        return;
    }

    // 连接服务器
    if (connect(client_socket, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to connect to the server!" << std::endl;
        return;
    }
    std::cout << "Connected to the server." << std::endl;

    try
    {
        string Y_str = receive_string(client_socket);
        string sigma_s = receive_string(client_socket);
        cout << "The sigma_s received in the client side " << sigma_s << endl;

        BLS bls;
        // bls.verify(Y_str, sigma_s);

        // Verify the signature
        bool is_valid = bls.verify(Y_str, sigma_s);
        std::cout << (is_valid ? "Signature is valid" : "Signature is invalid") << std::endl;

        NIZKProof nizk;
        // 2. 生成随机 alpha
        BIGNUM *r = BN_new();
        do
        {                                      // Prover chooses random r (scalar)
            BN_rand_range(r, nizk.getOrder()); // Generate random scalar r such that 0 <= r < order
        } while (BN_is_zero(r));

        Argon2iHasher argon2i;
        string argon2i_input = identity + password;

        // Generate a hash
        string hashedValue = argon2i.hashPassword(argon2i_input);

        // 将哈希值转换为椭圆曲线群元素
        EC_POINT *hashToGroup = ECGroupHasher::hashToGroupElement(hashedValue, nizk.getGroup(), nizk.getCtx(), nizk.getOrder());

        // Blind
        EC_POINT *alpha = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), alpha, NULL, hashToGroup, r, nizk.getCtx());
        nizk.setAlpha(alpha);

        // 3. 发送 alpha 到服务器
        send_string(client_socket, EC_POINT_point2hex(nizk.getGroup(), alpha, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx()));
        cout << "Alpha sent to the server: " << EC_POINT_point2hex(nizk.getGroup(), alpha, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx()) << endl;

        // 4. 接收 beta 和 NIZK 证明
        string beta_str = receive_string(client_socket);
        string pi_o_first = receive_string(client_socket);
        string pi_o_second_str = receive_string(client_socket);
        // string gk_str = receive_string(client_socket);

        nizk.setBeta(beta_str);
        cout << "Beta received from the server: " << beta_str << endl;
        BIGNUM *pi_o_second = BN_new();
        BN_hex2bn(&pi_o_second, pi_o_second_str.c_str());
        cout << "NIZK proof received from the server: " << pi_o_first << " " << pi_o_second_str << endl;

        // nizk.setGk(EC_POINT_hex2point(nizk.getGroup(), gk_str.c_str(), NULL, nizk.getCtx()));

        // Params
        cout << "Alpha: " << EC_POINT_point2hex(nizk.getGroup(), nizk.getAlpha(), POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx()) << endl;
        cout << "Beta: " << EC_POINT_point2hex(nizk.getGroup(), nizk.getBeta(), POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx()) << endl;

        // 5. 验证 NIZK
        if (nizk.verifyProof(pi_o_first, pi_o_second))
        {
            std::cout << "NIZK verification succeeded!" << std::endl;
        }
        else
        {
            std::cerr << "NIZK verification failed. Aborting test." << std::endl;

            BN_free(pi_o_second);
            EC_POINT_free(alpha);
            EC_POINT_free(hashToGroup);
            return;
        }
        cout << "spot 6" << endl;

        BIGNUM *rInverse = BN_new();
        BN_mod_inverse(rInverse, r, nizk.getOrder(), nizk.getCtx());

        cout << "spot 7" << endl;
        EC_POINT *unblind = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), unblind, NULL, NULL, rInverse, nizk.getCtx());
        cout << "spot 8" << endl;
        string hs = hashSHA256({password, EC_POINT_point2hex(nizk.getGroup(), unblind, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx())});
        cout << "spot 5" << endl;

        string rho = hashSHA256({identity, hs}).substr(0, identity.size());

        BIGNUM *x = BN_new();
        do
        {
            BN_rand_range(x, nizk.getOrder()); // Generate random k such that 0 <= k < order
        } while (BN_is_zero(x));
        cout << "spot 1" << endl;

        EC_POINT *X = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), X, x, NULL, NULL, nizk.getCtx());
        string X_str = EC_POINT_point2hex(nizk.getGroup(), X, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx());

        string sk_c_str = hashSHA256({"Sign", hs}).substr(0, 20);
        bls.set_secret_key(sk_c_str);
        string sigma_c = bls.sign(X_str + Y_str + sigma_s);
        // element_t sk;
        // bls.get_secret_key(sk);
        // element_printf("The secret key is %B\n", sk);
        // element_t pk;
        // bls.get_public_key(pk);
        // element_printf("The public key is %B\n", pk);

        send_string(client_socket, rho);
        send_string(client_socket, sigma_c);
        send_string(client_socket, X_str);

        EC_POINT *Y = EC_POINT_new(nizk.getGroup());
        Y = EC_POINT_hex2point(nizk.getGroup(), Y_str.c_str(), NULL, nizk.getCtx());

        EC_POINT *Yx = EC_POINT_new(nizk.getGroup());
        EC_POINT_mul(nizk.getGroup(), Yx, NULL, Y, x, nizk.getCtx());

        string k_se = hashSHA256({sigma_c.c_str(), sigma_s.c_str(), X_str.c_str(), Y_str.c_str(),
                                  EC_POINT_point2hex(nizk.getGroup(), Yx, POINT_CONVERSION_UNCOMPRESSED, nizk.getCtx())});

        cout << "The session key is exchanged!" << endl;

        vector<unsigned char> c_kek_vec = receive_binary(client_socket);
        vector<unsigned char> tag_vec = receive_binary(client_socket);

        // 重新转换回 unsigned char 数组
        unsigned char c_kek[c_kek_vec.size()];
        unsigned char tag[AESGCM::get_tag_size()];

        std::memcpy(c_kek, c_kek_vec.data(), c_kek_vec.size());
        std::memcpy(tag, tag_vec.data(), tag_vec.size());

        vector<unsigned char> k_ae = hashSHA256_key({"AE", hs});
        AESGCM aes_GCM;
        aes_GCM.set_key(k_ae);

        unsigned char k_kek[sizeof(c_kek)];
        bool dec_res = aes_GCM.decrypt(c_kek, sizeof(c_kek), tag, k_kek);

        vector<unsigned char> kek_vec(k_kek, k_kek + sizeof(k_kek));

        saveVectorToFile(kek_vec, "../Key/kek_recovered.dat");

        if (dec_res)
        {
            std::cout << "Decryption successful!" << std::endl;
            std::cout << "Decrypted text: ";
            for (unsigned char c : kek_vec)
            {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
            }
            cout << endl;
        }
        else
        {
            std::cerr << "Decryption failed!" << std::endl;
            return;
        }

        // 清理资源
        BN_free(r);
        BN_free(rInverse);
        BN_free(pi_o_second);
        EC_POINT_free(alpha);
        EC_POINT_free(unblind);
        EC_POINT_free(hashToGroup);
    }
    catch (const exception &ex)
    {
        std::cerr << "Error during client processing: " << ex.what() << std::endl;
    }

    close(client_socket);
    cout << "Login protocol completed successfully!" << std::endl;
}

// int main() {
//     string identity = "Teig_Sadhana";
//     string password12 = "i&23%^&*(HIF";
//     try {
//         client_test(identity, password12);
//     } catch (const std::exception& ex) {
//         std::cerr << "An error occurred during the test: " << ex.what() << endl;
//     }
//     return 0;
// }