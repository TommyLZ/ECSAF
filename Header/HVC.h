#pragma once
#include <pbc/pbc.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <libgen.h>
#include <filesystem>
#include <fstream>

using namespace std;
namespace fs = filesystem;

void saveZToFile(const std::string& filename, element_t* z) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    for (int i = 0; i <= 10; ++i) {
        // 假设元素可以通过 element_to_bytes 将其转换为字节数组
        size_t len = element_length_in_bytes(z[i]);
        std::vector<unsigned char> buffer(len);
        element_to_bytes(buffer.data(), z[i]);

        file.write(reinterpret_cast<char*>(buffer.data()), len);
    }
    file.close();
}


void loadZFromFile(const std::string& filename, element_t* z) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    for (int i = 0; i <= 10; ++i) {
        size_t len = element_length_in_bytes(z[i]);
        std::vector<unsigned char> buffer(len);

        file.read(reinterpret_cast<char*>(buffer.data()), len);
        if (file.gcount() != len) {
            throw std::runtime_error("Failed to read z_i from file");
        }

        element_from_bytes(z[i], buffer.data());
    }
    file.close();
}


class HVC {
private:
    pairing_t pairing;
    element_t* z;     // z_i
    element_t* h;     // h_i
    element_t** h_ij; // h_{i,j}
    element_t g;      // Generator
    int size;
    string g_file_path = "../Key/g.dat";
    string z_file = "../Key/z_i.dat";
    string param_file = "../Param/a.param";

public:
    // Constructor: Initialize pairing and setup
    HVC(int n): size(n) {
        // Load pairing parameters from file
        char param[1024];
        std::ifstream file(param_file, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open parameter file: " + param_file);
        }
        size_t count = file.readsome(param, sizeof(param));
        if (count == 0) {
            throw std::runtime_error("Failed to read parameter file: " + param_file);
        }
        pairing_init_set_buf(pairing, param, count);

        element_init_G1(g, pairing);

        // Load or generate g
        if (fs::exists(g_file_path)) {
            load_gen_from_file(g_file_path, g);
            element_printf("********The initialization of g is %B\n", g);
        } else {
            element_random(g);
            save_gen_to_file(g_file_path, g);
        }

        // Allocate memory for z and h
        z = new element_t[n + 1];
        for (int i = 0; i <= n; ++i) {
            element_init_Zr(z[i], pairing);
        }
        h = new element_t[n + 1];
        for (int i = 0; i <= n; ++i) {
            element_init_G1(h[i], pairing);
        }
        h_ij = new element_t*[n + 1];
        for (int i = 0; i <= n; ++i) {
            h_ij[i] = new element_t[n + 1];
            for (int j = 0; j<= n; ++j){
                element_init_G1(h_ij[i][j], pairing);
            }
        }

        // 尝试从文件加载 z_i
        try {
            cout << "Loaded z_i from file." << endl;
            loadZFromFile(z_file, z);
            setup(n);
        } catch (const std::runtime_error&) {
            cout << "Failed to load z_i from file. Generating new z_i..." << endl;
            // z_i
            for (int i = 0; i <= n; ++i) {
                element_random(z[i]);
            }
            setup(n);
            saveZToFile(z_file, z);  // 保存新的 z_i 到文件
            cout << "Saved new z_i to file." << endl;
        }
    }

    // Destructor: Clear memory
    ~HVC() {
        element_clear(g);

        for (int i = 0; i <= size; ++i) {
            element_clear(z[i]);
            element_clear(h[i]);
            for (int j = 0; j <= size; ++j) {
                if (i != j) element_clear(h_ij[i][j]);
            }
            delete[] h_ij[i];
        }
        delete[] z;
        delete[] h;
        delete[] h_ij;

        pairing_clear(pairing);
    }

    // Getter for pairing
    pairing_t& getPairing() {
        return pairing;
    }

    pairing_t& GetPairing() {
        return pairing;
    }

     // Setup Function
    void setup(int n) {
        for (int i = 0; i <= n; ++i) {
            // element_init_G1(h[i], pairing);
            element_pow_zn(h[i], g, z[i]);
        }

        // h_ij
        for (int i = 0; i <= n; ++i) {
            for (int j = 0; j <= n; ++j) {
                if (i != j) {
                    // element_init_G1(h_ij[i][j], pairing);
                    element_t tmp;
                    element_init_Zr(tmp, pairing);
                    element_mul(tmp, z[i], z[j]);
                    element_pow_zn(h_ij[i][j], g, tmp);
                    element_clear(tmp);
                }
            }
        }
        cout << "HVC.Setup completed." << endl;
    }

    // Commitment Function
    void commit(element_t* m, int n, element_t& C, element_t& r) {
        element_init_G1(C, pairing);
        element_init_Zr(r, pairing);
        element_random(r);
        element_set1(C);

        for (size_t i = 0; i < n; ++i) {
            element_t tmp;
            element_init_G1(tmp, pairing);
            element_pow_zn(tmp, h[i], m[i]); // Use m[i] directly
            element_mul(C, C, tmp);
            element_clear(tmp);
        }
        cout << "ss1" << endl;

        element_t h_r;
        element_init_G1(h_r, pairing);
        cout << "ss2" << endl;
        element_pow_zn(h_r, h[n-1], r);
        cout << "ss3" << endl;
        element_mul(C, C, h_r);
        element_clear(h_r);

        cout << "HVC.Com completed." << endl;
    }

    // Open Function
    void open(element_t* m, int n, int i, element_t& r, element_t& Lambda_i) {
        element_init_G1(Lambda_i, pairing);
        element_set1(Lambda_i);

        for (size_t j = 0; j < n; ++j) {
            if (j != i) {
                element_t tmp;
                element_init_G1(tmp, pairing);
                element_pow_zn(tmp, h_ij[i][j], m[j]); // Use m[j] directly
                element_mul(Lambda_i, Lambda_i, tmp);
                element_clear(tmp);
            }
        }

        element_t h_in_plus1;
        element_init_G1(h_in_plus1, pairing);
        element_pow_zn(h_in_plus1, h_ij[i][n-1], r);
        element_mul(Lambda_i, Lambda_i, h_in_plus1);
        element_clear(h_in_plus1);

        cout << "HVC.Open completed." << endl;
    }

    // Verification Function
    bool verify(element_t& C, element_t& m_i, element_t& Lambda_i, int i) {
        element_t left, right, tmp;
        element_init_GT(left, pairing);
        element_init_GT(right, pairing);
        element_init_G1(tmp, pairing);

        element_pow_zn(tmp, h[i], m_i); // Use m_i directly
        element_div(tmp, C, tmp);
        pairing_apply(left, tmp, h[i], pairing);
        pairing_apply(right, Lambda_i, g, pairing);

        bool result = !element_cmp(left, right);

        element_clear(left);
        element_clear(right);
        element_clear(tmp);

        return result;
    }

    // Homomorphic Combination for Commitments
    void comHom(element_t& C1, element_t& C2, element_t& C_out) {
        element_init_G1(C_out, pairing);
        element_mul(C_out, C1, C2); // C'' = C * C'
        cout << "HVC.ComHom completed." << endl;
    }

    // Homomorphic Combination for Opened Values
    void openHom(element_t& Lambda_j1, element_t& Lambda_j2, element_t& Lambda_j_out) {
        element_init_G1(Lambda_j_out, pairing);
        element_mul(Lambda_j_out, Lambda_j1, Lambda_j2); // Λ_j'' = Λ_j * Λ_j'
        cout << "HVC.OpenHom completed." << endl;
    }
};


// int main() {
//     // Set random seed
//     srand(time(0));

//     // Size of the commitment (e.g., 3 elements)
//     int n = 10;

//     cout << "s1" << endl;
//     // Initialize HVC with the specified size
//     HVC hvc(n);

//     cout << "s2" << endl;
//     // Create a message vector for commitment (use random values for m)
//     vector<element_t> m(n + 1);
//     for (int i = 0; i <= n; ++i) {
//         element_init_Zr(m[i], hvc.getPairing());
//         element_random(m[i]);
//     }

//     cout << "s3" << endl;
//     // Commitment: Create C and r
//     element_t C, r;
//     hvc.commit(m, C, r);

//     cout << "s4" << endl;    
//     // Open: Select an index i to open the commitment
//     int i = 2; // For example, let's open the commitment for the 2nd element
//     element_t Lambda_i;
//     hvc.open(m, i, r, Lambda_i);

//     cout << "s5" << endl;    
//     // Verification: Verify the commitment for the selected index i
//     bool verificationResult = hvc.verify(C, m[i], Lambda_i, i);
//     cout << "Verification result for index " << i << ": " << (verificationResult ? "Success" : "Failure") << endl;

//     // Test Homomorphic Combination for Commitments
//     element_t C1, C2, C_out;
//     hvc.commit(m, C1, r); // Commit for C1
//     hvc.commit(m, C2, r); // Commit for C2
//     hvc.comHom(C1, C2, C_out); // Combine C1 and C2 into C_out

//     // Test Homomorphic Combination for Opened Values
//     element_t Lambda_j1, Lambda_j2, Lambda_j_out;
//     hvc.open(m, 1, r, Lambda_j1); // Open for index 1
//     hvc.open(m, 2, r, Lambda_j2); // Open for index 2
//     hvc.openHom(Lambda_j1, Lambda_j2, Lambda_j_out); // Combine Lambda_j1 and Lambda_j2 into Lambda_j_out

//     cout << "Homomorphic combination for commitments and opened values completed successfully." << endl;

//     return 0;
// }