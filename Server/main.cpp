#include <iostream>
#include <chrono>
#include "Registraion_Server.h"
#include "Login_Server.h"
#include "Upload_Server.h"
#include "Query_Server.h"
#include "BatchQuery_server.h"
#include "FileUpdate_server.h"
#include "KeyUpdate_Server.h"
#include "Share_server.h"

int main()
{
    auto start = std::chrono::high_resolution_clock::now();
    server_registraion_test();
    // server_login_test();
    // server_upload_test();
    // server_query_test();
    // server_batchquery_test();
    // server_file_update();
    // server_key_update();
    // server_share();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "函数执行时间: " << elapsed.count() << " 秒" << std::endl;

    return 0;
}