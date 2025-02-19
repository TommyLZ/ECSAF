#pragma once
#include <pbc/pbc.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <libgen.h>

using namespace std;

class PedersenCommitment
{
private:
    pairing_t pairing;
    element_t g, h;  // Generators g and h in group G
    element_t order; // Group order p
    const string g_file_path = "../Key/g.dat"; // Path to store g
    const string h_file_path = "../Key/h.dat"; // Path to store h

public:
    // Setup function: Initialize public parameters
    PedersenCommitment()
    {
        const std::string param_file = "../Param/a.param";

        // Load pairing parameters from file
        char param[1024];
        std::ifstream file(param_file, std::ios::binary);
        if (!file)
        {
            throw std::runtime_error("Failed to open parameter file: " + param_file);
        }
        size_t count = file.readsome(param, sizeof(param));
        if (count == 0)
        {
            throw std::runtime_error("Failed to read parameter file: " + param_file);
        }
        pairing_init_set_buf(pairing, param, count);

        element_init_G1(g, pairing);
        element_init_G1(h, pairing);
        element_init_Zr(order, pairing);

        // Load or generate g
        if (filesystem::exists(g_file_path)&&filesystem::exists(h_file_path)) {
            load_gen_from_file(g_file_path, g);
            load_gen_from_file(h_file_path, h);
            element_printf("********The initialization of g is %B\n", g);
            element_printf("********The initialization of h is %B\n", h);
        } else {
            element_random(g);
            save_gen_to_file(g_file_path, g);
            element_random(h);
            save_gen_to_file(h_file_path, g);
        }

        std::cout << "Setup completed. Generators g and h initialized." << endl;
    }

    ~PedersenCommitment()
    {
        element_clear(g);
        element_clear(h);
        element_clear(order);
        pairing_clear(pairing);
    }

    // **🔥 Getter 方法**
    void getG(element_t &out_g)
    {
        element_init_G1(out_g, pairing);
        element_set(out_g, g);
    }

    void getH(element_t &out_h)
    {
        element_init_G1(out_h, pairing);
        element_set(out_h, h);
    }

    void getOrder(element_t &out_order)
    {
        element_init_Zr(out_order, pairing);
        element_set(out_order, order);
    }

    pairing_t &getPairing()
    {
        return pairing; // 直接返回 pairing_t 引用，避免拷贝
    }

    // **🔥 Setter 方法**
    void setG(element_t &new_g)
    {
        element_set(g, new_g);
    }

    void setH(element_t &new_h)
    {
        element_set(h, new_h);
    }

    void setOrder(element_t &new_order)
    {
        element_set(order, new_order);
    }

    // Commitment function: c = g^m * h^r
    void commit(element_t m, element_t &r, element_t &c)
    {
        element_init_Zr(r, pairing); // Random r in Zp

        element_random(r);           // Generate random r
        element_init_G1(c, pairing); // Commitment c in G1

        element_t g_m, h_r; // Temporary elements
        element_init_G1(g_m, pairing);
        element_init_G1(h_r, pairing);

        // element_t m;
        // element_init_Zr(m, pairing);
        // element_set_si(m, m_value); // Convert m_value to element in Zp

        // Compute g^m
        element_pow_zn(g_m, g, m);
        // Compute h^r
        element_pow_zn(h_r, h, r);

        // c = g^m * h^r
        element_mul(c, g_m, h_r);

        element_clear(g_m);
        element_clear(h_r);
        element_clear(m);

        std::cout << "Commitment generated." << endl;
    }

    // Verification function: check if c == g^m * h^r
    bool verify(element_t m, element_t &r, element_t &c)
    {
        element_t g_m, h_r, c_check;
        element_init_G1(g_m, pairing);
        element_init_G1(h_r, pairing);
        element_init_G1(c_check, pairing);

        // element_t m;
        // element_init_Zr(m, pairing);
        // element_set_si(m, m_value); // Convert m_value to element in Zp

        // Compute g^m and h^r
        element_pow_zn(g_m, g, m);
        element_pow_zn(h_r, h, r);

        // Compute c' = g^m * h^r
        element_mul(c_check, g_m, h_r);

        // Compare c and c'
        bool result = !element_cmp(c, c_check); // element_cmp returns 0 if equal

        // Clear temporary elements
        element_clear(g_m);
        element_clear(h_r);
        element_clear(c_check);
        element_clear(m);

        return result;
    }
};

// string getExecutablePath() {
//     char result[1024];
//     ssize_t count = readlink("/proc/self/exe", result, sizeof(result) - 1);
//     if (count != -1) {
//         result[count] = '\0';
//         return string(dirname(result));
//     }
//     return "";
// }

// int main() {
//     string paramPath = getExecutablePath() + "/Param/a.param";
//     PedersenCommitment pc(paramPath.c_str());

//     // Example message and commitment
//     int m_value = 42; // Example message m
//     element_t r, c;   // Random r and commitment c

//     // Generate commitment
//     pc.commit(m_value, r, c);

//     // Verify commitment
//     if (pc.verify(m_value, r, c)) {
//         cout << "Verification successful: Commitment is valid." << endl;
//     } else {
//         cout << "Verification failed: Commitment is invalid." << endl;
//     }

//     // Clear elements
//     element_clear(r);
//     element_clear(c);

//     return 0;
// }