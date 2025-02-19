#pragma once
#include <string>
#include <cstring>
#include <iostream>
#include <arpa/inet.h> // for socket functions
#include <unistd.h>    // for close()
#include <sys/socket.h>
#include <vector>

namespace fs = filesystem;

void send_string(int socket_fd, const std::string& data) {
    uint32_t length = htonl(data.size());
    if (send(socket_fd, &length, sizeof(length), 0) != sizeof(length)) {
        throw std::runtime_error("Failed to send string length");
    }

    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t bytes = send(socket_fd, data.c_str() + sent, data.size() - sent, 0);
        if (bytes <= 0) {
            throw std::runtime_error("Failed to send string data");
        }
        sent += bytes;
    }
}

// // 接收字符串数据
// std::string receive_string(int socket_fd) {
//     uint32_t length;
//     recv(socket_fd, &length, sizeof(length), 0); // 接收数据长度
//     length = ntohl(length);
//     char* buffer = new char[length + 1];
//     recv(socket_fd, buffer, length, 0); // 接收实际数据
//     buffer[length] = '\0';
//     std::string data(buffer);
//     delete[] buffer;
//     return data;
// }

string receive_string(int socket_fd) {
    uint32_t length;
    if (recv(socket_fd, &length, sizeof(length), 0) != sizeof(length)) {
        throw std::runtime_error("Failed to receive string length");
    }

    length = ntohl(length);
    std::vector<char> buffer(length);
    size_t received = 0;
    
    while (received < length) {
        ssize_t bytes = recv(socket_fd, buffer.data() + received, length - received, 0);
        if (bytes <= 0) {
            throw std::runtime_error("Connection lost or receive error");
        }
        received += bytes;
    }

    return std::string(buffer.begin(), buffer.end());
}


// 发送二进制数据
void send_binary(int socket_fd, const std::vector<unsigned char>& data) {
    uint32_t length = htonl(data.size());
    if (send(socket_fd, &length, sizeof(length), 0) != sizeof(length)) {
        throw std::runtime_error("Failed to send binary data length");
    }

    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t bytes = send(socket_fd, data.data() + sent, data.size() - sent, 0);
        if (bytes <= 0) {
            throw std::runtime_error("Failed to send binary data");
        }
        sent += bytes;
    }
}

std::vector<unsigned char> receive_binary(int socket_fd) {
    uint32_t length;
    if (recv(socket_fd, &length, sizeof(length), 0) != sizeof(length)) {
        throw std::runtime_error("Failed to receive binary data length");
    }

    length = ntohl(length);
    std::vector<unsigned char> data(length);
    size_t received = 0;

    while (received < length) {
        ssize_t bytes = recv(socket_fd, data.data() + received, length - received, 0);
        if (bytes <= 0) {
            throw std::runtime_error("Connection lost or receive error");
        }
        received += bytes;
    }

    return data;
}

// 发送文件
void send_file(int socket_fd, const string& file_path) {
    ifstream file(file_path, ios::binary);
    if (!file) {
        cerr << "Failed to open file: " << file_path << endl;
        return;
    }

    // 读取文件内容
    vector<unsigned char> buffer((istreambuf_iterator<char>(file)), {});
    
    // 发送文件名
    send_string(socket_fd, fs::path(file_path).filename().string());
    
    // 发送文件内容
    send_binary(socket_fd, buffer);
    
    cout << "Sent: " << file_path << endl;

    send_string(socket_fd, "");
}

// 发送文件夹下的所有文件
void send_folder(int socket_fd, const string& folder_path) {
    for (const auto& entry : fs::directory_iterator(folder_path)) {
        if (fs::is_regular_file(entry.path())) {
            send_file(socket_fd, entry.path().string());
        }
    }
    
    // 发送结束标志（空文件名）
    send_string(socket_fd, "");
    cout << "All files sent." << endl;
}

// 接收文件
void receive_file(int socket_fd, const string& save_folder) {
    while (true) {
        // 读取文件名
        string filename = receive_string(socket_fd);
        if (filename.empty()) {
            cout << "All files received." << endl;
            break;
        }

        // 读取文件内容
        vector<unsigned char> data = receive_binary(socket_fd);

        // 保存文件
        string save_path = save_folder + "/" + filename;
        ofstream file(save_path, ios::binary);
        file.write(reinterpret_cast<char*>(data.data()), data.size());
        
        cout << "Received: " << save_path << endl;
    }
}

void send_element(int socket_fd, element_t elem) {
    int len = element_length_in_bytes(elem); // 获取字节长度
    std::vector<unsigned char> buffer(len);
    element_to_bytes(buffer.data(), elem);  // 转换为字节数组

    send_binary(socket_fd, buffer); // 发送
}

void receive_element(int socket_fd, element_t elem) {
    std::vector<unsigned char> buffer = receive_binary(socket_fd); // 接收数据
    element_from_bytes(elem, buffer.data()); // 还原 `element_t`
}