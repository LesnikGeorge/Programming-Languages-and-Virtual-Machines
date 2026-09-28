#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <numeric>
#include <random>
#include <algorithm>
#include <string>
#include <cstdlib>

volatile size_t prevent_optimization = 0;

std::string get_sysfs_value(const std::string& path) {
    std::ifstream file(path);
    std::string value;
    if (file >> value) return value;
    return "Unknown";
}

void setup_linear_chasing(size_t* array, size_t size_bytes, size_t stride_bytes) {
    size_t num_elements = size_bytes / sizeof(size_t);
    size_t stride = stride_bytes / sizeof(size_t);
    for (size_t i = 0; i < num_elements; i++) {
        array[i] = (i + stride) % num_elements;
    }
}

void setup_chasing(size_t* array, size_t size_bytes, size_t stride_bytes) {
    size_t num_elements = size_bytes / sizeof(size_t);
    size_t stride = stride_bytes / sizeof(size_t);
    size_t num_blocks = size_bytes / stride_bytes;

    if (num_blocks <= 1) return;

    std::vector<size_t> blocks(num_blocks);
    std::iota(blocks.begin(), blocks.end(), 0);
    
    std::mt19937 rng(19937);
    std::shuffle(blocks.begin(), blocks.end(), rng);

    for (size_t i = 0; i < num_blocks - 1; ++i) {
        array[blocks[i] * stride] = blocks[i + 1] * stride;
    }
    array[blocks[num_blocks - 1] * stride] = blocks[0] * stride;
}

double measure(size_t* array) {
    const int ITERATIONS = 50000000;
    double best_time = 9999.0;
    
    for (int run = 0; run < 2; ++run) {
        size_t index = 0;
        auto start = std::chrono::steady_clock::now();
        
        for (int i = 0; i < ITERATIONS; ++i) {
            index = array[index];
        }
        
        auto end = std::chrono::steady_clock::now();
        prevent_optimization = index;
        
        std::chrono::duration<double, std::nano> duration = end - start;
        double t = duration.count() / ITERATIONS;
        if (t < best_time) best_time = t;
    }
    return best_time;
}

int main() {
    //Я на Убунту у себя правильные ответы смотрел
    /*std::string line_size_sys = get_sysfs_value("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size");
    std::string l1_size_sys = get_sysfs_value("/sys/devices/system/cpu/cpu0/cache/index0/size");
    std::string ways_sys = get_sysfs_value("/sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity");

    std::cout << "Determined without calculation\n";
    std::cout << "Line size: " << line_size_sys << " bytes\n";
    std::cout << "L1 cache size: " << l1_size_sys << "\n";
    std::cout << "Associativity: " << ways_sys << "-way\n\n";*/

    size_t MAX_MEM = 16 * 1024 * 1024;
    size_t* arr = (size_t*)std::aligned_alloc(4096, MAX_MEM);

    size_t calc_line_size = 64;
    double prev_time = 0.0;
    double baseline = 0.0;
    
    for (size_t stride = 8; stride <= 256; stride *= 2) {
        setup_linear_chasing(arr, 4 * 1024 * 1024, stride);
        double t = measure(arr);
        
        if (stride == 8) baseline = t;
        
        if (stride > 8 && t < prev_time * 1.05 && t > baseline * 1.50) {
            calc_line_size = stride / 2;
            break;
        }
        prev_time = t;
    }

    size_t calc_l1_size = 32 * 1024;
    double min_time = 9999.0;
    
    for (size_t size = 4 * 1024; size <= 256 * 1024; size *= 2) {
        setup_chasing(arr, size, calc_line_size);
        double t = measure(arr);
        
        if (t < min_time) min_time = t;
        if (t > min_time * 1.50) {
            calc_l1_size = size / 2;
            break;
        }
    }

    size_t calc_ways = 8;
    min_time = 9999.0;
    
    for (int ways = 2; ways <= 32; ways++) {
        setup_chasing(arr, ways * calc_l1_size, calc_l1_size);
        double t = measure(arr);
        
        if (t < min_time) min_time = t;
        if (t > min_time * 1.50) {
            calc_ways = ways - 1;
            break;
        }
    }

    std::cout << "Calculated\n";
    std::cout << "Line size: " << calc_line_size << " bytes\n";
    std::cout << "L1 cache size: " << calc_l1_size / 1024 << " KB\n";
    std::cout << "Associativity: " << calc_ways << "-way\n";

    std::free(arr);
    return 0;
}