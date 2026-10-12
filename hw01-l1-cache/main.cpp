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
    const int ITERATIONS = 10000000;
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

struct CacheResult {
    size_t line_size;
    size_t l1_size;
    size_t ways;

    bool operator==(const CacheResult& other) const {
        return line_size == other.line_size && 
               l1_size == other.l1_size && 
               ways == other.ways;
    }
};

CacheResult compute_once(size_t* arr) {
    std::vector<double> line_times;
    std::vector<size_t> strides_tested;
    for (size_t stride = 8; stride <= 256; stride *= 2) {
        setup_linear_chasing(arr, 4 * 1024 * 1024, stride);
        line_times.push_back(measure(arr));
        strides_tested.push_back(stride);
    }
    
    size_t calc_line_size = 64;
    double max_line_jump = 0;

    for (size_t i = 1; i < line_times.size(); i++) {
        double jump = line_times[i] / line_times[i - 1];
        if (jump > max_line_jump) {
            max_line_jump = jump;
            calc_line_size = strides_tested[i];
        }
    }



    std::vector<double> l1_times;
    std::vector<size_t> sizes_tested = {
        4*1024, 8*1024, 12*1024, 16*1024, 24*1024, 32*1024, 
        48*1024, 64*1024, 96*1024, 128*1024, 192*1024, 256*1024, 384*1024, 512*1024
    };

    for (size_t size : sizes_tested) {
        setup_chasing(arr, size, calc_line_size);
        l1_times.push_back(measure(arr));
    }

    size_t calc_l1_size = 32 * 1024;
    double max_l1_jump = 0;

    for (size_t i = 1; i < l1_times.size(); i++) {
        double jump = l1_times[i] / l1_times[i-1];
        if (jump > max_l1_jump) {
            max_l1_jump = jump;
            calc_l1_size = sizes_tested[i-1];
        }
    }



    std::vector<double> ways_times;
    std::vector<int> ways_tested;
    for (int ways = 2; ways <= 32; ways++) {
        setup_chasing(arr, ways * calc_l1_size, calc_l1_size);
        ways_times.push_back(measure(arr));
        ways_tested.push_back(ways);
    }

    size_t calc_ways = 8;
    double max_ways_jump = 0;

    for (size_t i = 1; i < ways_times.size(); i++) {
        double jump = ways_times[i] / ways_times[i-1];
        if (jump > max_ways_jump) {
            max_ways_jump = jump;
            calc_ways = ways_tested[i-1];
        }
    }

    //можно смотреть результаты итераций
    /*std::cout << "Calc, no final\n";
    std::cout << "Line size: " << calc_line_size << " bytes\n";
    std::cout << "L1 cache size: " << calc_l1_size / 1024 << " KB\n";
    std::cout << "Associativity: " << calc_ways << "-way\n\n";*/

    return {calc_line_size, calc_l1_size, calc_ways};
}

int main() {
    //Я на ubuntu у себя правильные ответы смотрел
    /*std::string line_size_sys = get_sysfs_value("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size");
    std::string l1_size_sys = get_sysfs_value("/sys/devices/system/cpu/cpu0/cache/index0/size");
    std::string ways_sys = get_sysfs_value("/sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity");

    std::cout << "Determined without calculation\n";
    std::cout << "Line size: " << line_size_sys << " bytes\n";
    std::cout << "L1 cache size: " << l1_size_sys << "\n";
    std::cout << "Associativity: " << ways_sys << "-way\n\n";*/

    size_t MAX_MEM = 16 * 1024 * 1024;
    size_t* arr = (size_t*)std::aligned_alloc(4096, MAX_MEM);

    std::vector<CacheResult> history;
    CacheResult final_res;

    //проверка на 2 из 3, либо первый с 3, либо любой с 2 если за 12 итераций не успели
    int attempts = 0;
    while (attempts++ < 12) {
        CacheResult res = compute_once(arr);
        history.push_back(res);

        if (history.size() >= 3) {
            bool found = false;
            for (const auto& candidate : history) {
                int count = 0;
                for (const auto& item : history) {
                    if (candidate == item) count++;
                }

                if (count >= 2) {
                    final_res = candidate;

                    if (history.size() == 3 && count >= 2) {
                        found = true;
                        break;
                    }
                    
                    if (history.size() > 3 && count >= 3) {
                        found = true;
                        break;
                    }
                }

                
                
            }
            if (found) break;
        }
    }

    std::cout << "Calculated\n";
    std::cout << "Line size: " << final_res.line_size << " bytes\n";
    std::cout << "L1 cache size: " << final_res.l1_size / 1024 << " KB\n";
    std::cout << "Associativity: " << final_res.ways << "-way\n";

    std::free(arr);
    return 0;
}