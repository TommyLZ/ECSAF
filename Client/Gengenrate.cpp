#include <pbc/pbc.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

#define FILE_SIZE 1024  // 1KB
#define NUM_FILES 10    // 生成10个文件

int main()
{
    // 初始化配对参数
    pairing_t pairing;
    const std::string param_file = "./Param/a.param";

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

    // 生成10个文件，每个文件大小为1KB
    for (int file_index = 0; file_index < NUM_FILES; ++file_index)
    {
        // 文件路径
        char filename[64];
        sprintf(filename, "./Repository/R2/g1_elements_%d.dat", file_index);
        std::ofstream outfile(filename, std::ios::binary);
        if (!outfile)
        {
            std::cerr << "Error opening file " << filename << " for writing." << std::endl;
            return 1;
        }

        // 当前文件大小
        size_t current_size = 0;

        // 持续生成元素，直到文件大小达到1KB
        while (current_size < FILE_SIZE)
        {
            // 生成一个新的G1元素
            element_t g1_element;
            element_init_G1(g1_element, pairing);
            element_random(g1_element); // 随机生成G1元素

            // 序列化G1元素
            unsigned char buffer[FILE_SIZE];
            size_t written = element_to_bytes(buffer, g1_element);

            // 如果当前序列化的元素小于文件剩余空间，写入文件
            size_t space_left = FILE_SIZE - current_size;
            size_t write_size = std::min(written, space_left);

            outfile.write(reinterpret_cast<char *>(buffer), write_size); // 写入文件
            current_size += write_size;

            element_clear(g1_element); // 清理内存

            // 输出当前进度
            std::cout << "File " << filename << ": Wrote " << write_size << " bytes, total file size: " << current_size << " bytes." << std::endl;
        }

        // 关闭文件
        outfile.close();
        std::cout << "File " << filename << " has reached 1KB." << std::endl;
    }

    // 清理内存
    pairing_clear(pairing);

    return 0;
}
