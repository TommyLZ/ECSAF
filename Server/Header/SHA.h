#pragma once

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

using namespace std;

// Helper function to compute SHA-256 hash using EVP interface
std::string hashSHA256(const std::vector<std::string>& inputs) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new(); // Create EVP context
    const EVP_MD* sha256 = EVP_sha256(); // Get SHA-256 digest method
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Initialize EVP context for SHA-256
    if (!EVP_DigestInit_ex(ctx, sha256, NULL)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Update the hash with each input
    for (const auto& input : inputs) {
        if (!EVP_DigestUpdate(ctx, input.c_str(), input.size())) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }

    // Finalize the hash
    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx); // Clean up the context

    // Convert hash to hexadecimal string
    std::ostringstream hashStream;
    for (unsigned int i = 0; i < hash_len; ++i) {
        hashStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return hashStream.str();
}
