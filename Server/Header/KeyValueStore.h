#pragma once 
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <filesystem>

class JsonFileHandler {
private:
    string filePath;

public:
    // 构造函数
    JsonFileHandler(const string& path) : filePath(path) {
        // 如果路径目录不存在，创建目录
        std::filesystem::create_directories(std::filesystem::path(filePath).parent_path());
    }

    // // 写入 JSON 数据到文件
    // void write(const nlohmann::json& data) {
    //     std::ifstream inputFile(filePath);
    //     nlohmann::json existingData;

    //     // 如果文件存在且不为空，读取现有数据
    //     if (inputFile.is_open() && inputFile.peek() != std::ifstream::traits_type::eof()) {
    //         inputFile >> existingData;
    //     }
    //     inputFile.close();

    //     // 确保文件存储为数组格式
    //     if (!existingData.is_array()) {
    //         existingData = nlohmann::json::array();
    //     }

    //     // 追加新的数据
    //     existingData.push_back(data);

    //     // 写入更新后的数据
    //     std::ofstream file(filePath, ios::out | ios::trunc); // 覆盖写入
    //     if (!file.is_open()) {
    //         throw std::runtime_error("无法打开文件进行写入: " + filePath);
    //     }

    //     file << existingData.dump(4); // 写入格式化 JSON
    //     file.close();
    //     std::cout << "数据已写入文件: " << filePath << std::endl;
    // }


    // nlohmann::json readByRho(const std::string& rhoKey) {
    //     std::ifstream inputFile(filePath);
    //     if (!inputFile.is_open()) {
    //         throw std::runtime_error("无法打开文件进行读取: " + filePath);
    //     }

    //     nlohmann::json data;
    //     inputFile >> data; // 读取整个 JSON 文件
    //     inputFile.close();

    //     if (!data.is_array()) {
    //         throw std::runtime_error("文件数据不是 JSON 数组格式");
    //     }

    //     // 遍历数组查找匹配的 rho
    //     for (const auto& item : data) {
    //         if (item.contains(rhoKey)) {
    //             return item[rhoKey]; // 返回匹配的 JSON 数据
    //         }
    //     }

    //     throw std::runtime_error("未找到匹配的 rho: " + rhoKey);
    // }

    void write(const nlohmann::json& data) {
        nlohmann::json existingData;


        cout << "sppt3" << endl;   
        // 读取原始 JSON 数据（如果文件存在）
        if (std::filesystem::exists(filePath)) {
            std::ifstream inputFile(filePath);
            if (inputFile.is_open() && inputFile.peek() != std::ifstream::traits_type::eof()) {
                inputFile >> existingData;
            }
            inputFile.close();
        }

        cout << "sppt2" << endl;        

        // 确保 existingData 是 JSON 对象
        if (!existingData.is_object()) {
            existingData = nlohmann::json::object();
        }

        // 合并新数据
        existingData.update(data);

        cout << "sppt1" << endl;

        // 重新写入 JSON
        std::ofstream file(filePath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("无法打开文件进行写入: " + filePath);
        }

        file << existingData.dump(4); // 格式化 JSON
        file.close();
        std::cout << "数据已写入文件: " << filePath << std::endl;
    }

    nlohmann::json readByRho(const std::string& rhoKey) {
        std::ifstream inputFile(filePath);
        if (!inputFile.is_open()) {
            throw std::runtime_error("无法打开文件进行读取: " + filePath);
        }

        nlohmann::json data;
        inputFile >> data; // 读取整个 JSON 文件
        inputFile.close();

        if (!data.is_object()) {
            throw std::runtime_error("文件数据不是 JSON 对象格式");
        }

        // 查找 rhoKey
        if (data.contains(rhoKey)) {
            return data[rhoKey]; // 返回匹配的 JSON 数据
        }

        throw std::runtime_error("未找到匹配的 rho: " + rhoKey);
    }

};