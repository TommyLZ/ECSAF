#pragma once

#include <sodium.h>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace std;

class Argon2iHasher {
public:
    // Constructor to initialize libsodium
    Argon2iHasher() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    // Function to hash a password
    std::string hashPassword(const std::string& password) const {
        char hashedPassword[crypto_pwhash_STRBYTES];

        // Perform password hashing
        if (crypto_pwhash_str(
                hashedPassword,
                password.c_str(),
                password.length(),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,  // Time cost
                crypto_pwhash_MEMLIMIT_INTERACTIVE)  // Memory cost
            != 0) {
            throw std::runtime_error("Password hashing failed");
        }

        return std::string(hashedPassword);
    }

    // Function to verify a password against a hash
    bool verifyPassword(const std::string& hashedPassword, const std::string& password) const {
        return crypto_pwhash_str_verify(
                   hashedPassword.c_str(),
                   password.c_str(),
                   password.length()) == 0;
    }
};

// int main() {
//     try {
//         Argon2iHasher hasher;

//         // Password to hash
//         std::string password = "my_secure_password";

//         // Generate a hash
//         std::string hashedPassword = hasher.hashPassword(password);
//         std::cout << "Hashed password: " << hashedPassword << std::endl;

//         // Verify the password
//         if (hasher.verifyPassword(hashedPassword, password)) {
//             std::cout << "Password verified successfully!" << std::endl;
//         } else {
//             std::cout << "Password verification failed!" << std::endl;
//         }
//     } catch (const std::exception& ex) {
//         std::cerr << "Error: " << ex.what() << std::endl;
//     }

//     return 0;
// }