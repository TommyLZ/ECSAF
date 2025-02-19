#pragma once

#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <fstream>
#include "IOUtils.h"
#include "SHA.h"

using namespace std;

// NIZKProof class definition
class NIZKProof
{
private:
    EC_GROUP *group; // EC group (secp256k1)
    BIGNUM *order;   // EC group order
    EC_POINT *g;     // Base point (generator) on the curve
    EC_POINT *gk;    // Public point related to secret key
    EC_POINT *alpha; // A point related to secret key
    EC_POINT *beta;  // Another public point on the curve
    BIGNUM *k;       // Secret key (in scalar form)
    BN_CTX *ctx;     // Context for big number operations
    string k_file;   // File to store k
    string gk_file;  // File to store gk

public:
    // Constructor: Initialize parameters
    NIZKProof()
    {
        ctx = BN_CTX_new();

        // Initialize EC group for secp256k1 curve
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (group == NULL)
        {
            throw std::runtime_error("Failed to initialize secp256k1 group");
        }

        order = BN_new(); // Create a BIGNUM to store the group order
        if (EC_GROUP_get_order(group, order, ctx) == 0)
        {
            throw std::runtime_error("Failed to get group order");
        }

        g = EC_POINT_new(group);  // Base point (generator)
        gk = EC_POINT_new(group); // Public point
        alpha = nullptr;          // Not initialized here
        beta = nullptr;           // Not initialized here
        // k_file = "../Key/Server_key.dat";
        gk_file = "../Key/Server_public_key.dat";

        // // Read or generate the random scalar k
        k = BN_new();
        // if (!readKFromFile(k, k_file)) {
        //     do {
        //         BN_rand_range(k, order);  // Generate random k such that 0 <= k < order
        //     } while (BN_is_zero(k));

        //     writeInFile(k, k_file);  // Generate and store k if not found
        // }

        // Set the base point (generator)
        EC_POINT_copy(g, EC_GROUP_get0_generator(group));

        // // // Compute gk = k * G
        // // EC_POINT_mul(group, gk, k, NULL, NULL, ctx);

        if (!readECPointFromFile(group, gk, gk_file, ctx))
        {
            cout << "The NIZK public parameter does not exist!" << endl;
            return;
        }
    }

    // Destructor: Free resources
    ~NIZKProof()
    {
        EC_POINT_free(g);
        EC_POINT_free(gk);
        if (alpha)
            EC_POINT_free(alpha);
        if (beta)
            EC_POINT_free(beta);
        BN_free(k);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
    }

    // Get the group
    EC_GROUP *getGroup() const
    {
        return group;
    }

    // Get the context
    BN_CTX *getCtx() const
    {
        return ctx;
    }

    // Get the generator
    EC_POINT *getGenerator() const
    {
        return g;
    }

    // Get the group order
    BIGNUM *getOrder() const
    {
        return order;
    }

    // Get the beta
    EC_POINT *getAlpha()
    {
        return alpha;
    }

    // Get the beta
    EC_POINT *getBeta()
    {
        return beta;
    }

    // Set alpha
    void setAlpha(const EC_POINT *new_alpha)
    {
        if (alpha)
        {
            EC_POINT_free(alpha);
        }
        alpha = EC_POINT_dup(new_alpha, group); // Create a copy of the point
        if (alpha == NULL)
        {
            throw std::runtime_error("Failed to set alpha");
        }
    }

    // Set beta
    void setBeta(const EC_POINT *alpha)
    {
        if (!beta)
        {
            beta = EC_POINT_new(group); // 确保 beta 被初始化
        }
        EC_POINT_mul(group, beta, NULL, alpha, k, ctx); // beta = k * alpha
        if (beta == NULL)
        {
            throw runtime_error("Failed to set beta");
        }
    }

    // Set beta
    void setBeta(const string &beta_str)
    {
        if (!beta)
        {
            beta = EC_POINT_new(group); // 确保 beta 被初始化
        }
        beta = EC_POINT_hex2point(group, beta_str.c_str(), NULL, ctx);
        if (beta == NULL)
        {
            throw runtime_error("Failed to set beta");
        }
    }

    // Verify proof
    bool verifyProof(const std::string &c_hash, BIGNUM *u)
    {
        if (!alpha || !beta)
        {
            throw std::runtime_error("alpha or beta is not set");
        }

        BIGNUM *c = BN_new();
        EC_POINT *t1_prime = EC_POINT_new(group);
        EC_POINT *t2_prime = EC_POINT_new(group);
        EC_POINT *tmp1 = EC_POINT_new(group);
        EC_POINT *tmp2 = EC_POINT_new(group);

        // Convert c_hash back to BIGNUM
        BN_hex2bn(&c, c_hash.c_str());

        cout << "In nizk: " << EC_POINT_point2hex(group, gk, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;

        // Compute t1' = g * u + gk * c
        EC_POINT_mul(group, tmp1, u, NULL, NULL, ctx);
        EC_POINT_mul(group, tmp2, NULL, gk, c, ctx);
        EC_POINT_add(group, t1_prime, tmp1, tmp2, ctx);

        // Compute t2' = alpha * u + beta * c
        EC_POINT_mul(group, tmp1, NULL, alpha, u, ctx);
        EC_POINT_mul(group, tmp2, NULL, beta, c, ctx);
        EC_POINT_add(group, t2_prime, tmp1, tmp2, ctx);

        // Compute c' = H3(g, gk, alpha, beta, t1', t2')
        std::string c_prime_hash = hashSHA256({EC_POINT_point2hex(group, g, POINT_CONVERSION_UNCOMPRESSED, ctx), EC_POINT_point2hex(group, gk, POINT_CONVERSION_UNCOMPRESSED, ctx),
                                               EC_POINT_point2hex(group, alpha, POINT_CONVERSION_UNCOMPRESSED, ctx), EC_POINT_point2hex(group, beta, POINT_CONVERSION_UNCOMPRESSED, ctx),
                                               EC_POINT_point2hex(group, t1_prime, POINT_CONVERSION_UNCOMPRESSED, ctx), EC_POINT_point2hex(group, t2_prime, POINT_CONVERSION_UNCOMPRESSED, ctx)});

        // Hash para:
        cout << "g: " << EC_POINT_point2hex(group, g, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
        cout << "gk: " << EC_POINT_point2hex(group, gk, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
        cout << "alpha: " << EC_POINT_point2hex(group, alpha, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
        cout << "beta: " << EC_POINT_point2hex(group, beta, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
        cout << "t1: " << EC_POINT_point2hex(group, t1_prime, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;
        cout << "t2: " << EC_POINT_point2hex(group, t2_prime, POINT_CONVERSION_UNCOMPRESSED, ctx) << endl;

        // Clean up
        BN_free(c);
        EC_POINT_free(t1_prime);
        EC_POINT_free(t2_prime);
        EC_POINT_free(tmp1);
        EC_POINT_free(tmp2);

        // Verify if c == c'
        return (c_hash == c_prime_hash);
    }
};

// int main() {
//     try {
//         NIZKProof nizk;

//         // Dynamically set alpha and beta
//         EC_POINT* alpha = EC_POINT_new(nizk.getGroup());
//         if (!alpha) {
//             throw std::runtime_error("Failed to allocate alpha");
//         }

//         // Initialize alpha
//         if (EC_POINT_mul(nizk.getGroup(), alpha, NULL, nizk.getGenerator(), BN_value_one(), nizk.getCtx()) == 0) {
//             EC_POINT_free(alpha);
//             throw std::runtime_error("Failed to initialize alpha");
//         }

//         nizk.setAlpha(alpha);
//         nizk.setBeta(alpha);

//         // Generate and verify proof
//         auto proof = nizk.generateProof();
//         if (nizk.verifyProof(proof.first, proof.second)) {
//             std::cout << "Verification succeeded!" << std::endl;
//         } else {
//             std::cout << "Verification failed!" << std::endl;
//         }

//         // Clean up
//         EC_POINT_free(alpha);
//         // EC_POINT_free(beta);
//     } catch (const std::exception& e) {
//         std::cerr << "Error: " << e.what() << std::endl;
//     }
//     return 0;
// }