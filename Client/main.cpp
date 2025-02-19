#include <iostream>
#include <cstring>
#include <chrono>
#include "Registraion_Client.h"
#include "Login_Client.h"
#include "Upload_Client.h"
#include "Query_Client.h"
#include "BatchQuery_client.h"
#include "FileUpdate_client.h"
#include "KeyUpdate_client.h"
#include "Share_client.h"

int main()
{
    string identity = "Teig_Sadhana";
    string password12 = "i&23%^&*(HIF";

    auto start = std::chrono::high_resolution_clock::now();
    client_registration_test(identity, password12);
    // client_login_test(identity, password12);
    // client_upload_test();
    // client_query_test();
    // client_batchquery_test();
    // client_file_update();
    // client_key_update();
    // client_share();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "函数执行时间: " << elapsed.count() << " 秒" << std::endl;

    return 0;
}