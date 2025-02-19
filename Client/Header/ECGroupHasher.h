#pragma once
#include <iostream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <stdexcept>
#include <string>
#include "Argon2i.h"

class ECGroupHasher {
public:
    // 将字符串哈希值转换为椭圆曲线群元素
    static EC_POINT* hashToGroupElement(const std::string& hash, EC_GROUP* group, BN_CTX* ctx, BIGNUM* order) {
        if (!group || !ctx || !order) {
            throw std::invalid_argument("Invalid group, context, or order");
        }

        // 转换哈希值为 BIGNUM
        BIGNUM* hashBN = BN_new();
        if (!BN_bin2bn(reinterpret_cast<const unsigned char*>(hash.data()), hash.size(), hashBN)) {
            throw std::runtime_error("Failed to convert hash to BIGNUM");
        }

        // 取模操作，确保哈希值在群的范围内
        BIGNUM* scalar = BN_new();
        if (!BN_mod(scalar, hashBN, order, ctx)) {
            BN_free(hashBN);
            throw std::runtime_error("Failed to reduce hash modulo group order");
        }

        // 使用基点生成群元素
        EC_POINT* point = EC_POINT_new(group);
        if (!EC_POINT_mul(group, point, scalar, NULL, NULL, ctx)) {
            BN_free(hashBN);
            BN_free(scalar);
            EC_POINT_free(point);
            throw std::runtime_error("Failed to generate EC point");
        }

        // 清理资源
        BN_free(hashBN);
        BN_free(scalar);

        return point;
    }
};

// int main() {
//     try {
//         // 初始化椭圆曲线相关参数
//         EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
//         if (!group) {
//             throw std::runtime_error("Failed to create EC group");
//         }
//         BN_CTX* ctx = BN_CTX_new();
//         BIGNUM* order = BN_new();
//         if (!EC_GROUP_get_order(group, order, ctx)) {
//             throw std::runtime_error("Failed to get group order");
//         }

//         // 哈希输入
//         Argon2iHasher hasher;
//         std::string identity = "test_user";
//         std::string password = "secure_password";
//         std::string hashInput = identity + password;

//         // 使用 Argon2iHasher 生成哈希值
//         std::string hashedValue = hasher.hashPassword(hashInput);
//         std::cout << "Hashed value: " << hashedValue << std::endl;

//         // 将哈希值转换为椭圆曲线群元素
//         EC_POINT* point = ECGroupHasher::hashToGroupElement(hashedValue, group, ctx, order);

//         // 输出群元素（使用未压缩形式）
//         char* pointStr = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);
//         std::cout << "Group element (EC_POINT): " << pointStr << std::endl;

//         // 清理资源
//         OPENSSL_free(pointStr);
//         EC_POINT_free(point);
//         BN_free(order);
//         BN_CTX_free(ctx);
//         EC_GROUP_free(group);
//     } catch (const std::exception& ex) {
//         std::cerr << "Error: " << ex.what() << std::endl;
//         return 1;
//     }

//     return 0;
// }
