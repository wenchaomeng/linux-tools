#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>

#define MB (1024 * 1024)
#define GB (1024 * MB)
#define DEFAULT_SIZE (100 * MB)
#define DEFAULT_ITERATIONS 10
#define CACHE_LINE_SIZE 64

// 测试配置
typedef struct {
    size_t buffer_size;
    int iterations;
    int num_threads;
    int affinity;
    int verbose;
} test_config_t;

// 测试结果
typedef struct {
    double read_bandwidth;    // MB/s
    double write_bandwidth;   // MB/s
    double copy_bandwidth;    // MB/s
    double scale_bandwidth;   // MB/s
    double add_bandwidth;     // MB/s
    double triad_bandwidth;   // MB/s
} bandwidth_result_t;

// 全局配置
test_config_t config = {
    .buffer_size = DEFAULT_SIZE,
    .iterations = DEFAULT_ITERATIONS,
    .num_threads = 1,
    .affinity = 0,
    .verbose = 0
};

// 获取当前时间（微秒）
static inline double get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

// 设置线程亲和性
void set_thread_affinity(int cpu_id) {
    if (!config.affinity) return;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
        perror("Failed to set thread affinity");
    }
}

// 内存读取带宽测试
double test_read_bandwidth(char *buffer, size_t size) {
    volatile char sink = 0;
    double start_time, end_time, total_time = 0;
    size_t bytes_per_iteration = size;
    
    // 预热缓存
    for (size_t i = 0; i < size; i += CACHE_LINE_SIZE) {
        sink += buffer[i];
    }
    
    for (int iter = 0; iter < config.iterations; iter++) {
        start_time = get_time_us();
        
        // 读取内存，避免编译器优化
        for (size_t i = 0; i < size; i += CACHE_LINE_SIZE) {
            sink += buffer[i];
        }
        
        end_time = get_time_us();
        total_time += (end_time - start_time);
    }
    
    // 防止编译器优化掉 sink
    if (sink == 0) printf(" ");
    
    double avg_time_us = total_time / config.iterations;
    double bandwidth_mbps = (bytes_per_iteration / avg_time_us) * 1000000.0 / MB;
    
    if (config.verbose) {
        printf("Read test: %zu bytes in %.2f us, bandwidth: %.2f MB/s\n", 
               bytes_per_iteration, avg_time_us, bandwidth_mbps);
    }
    
    return bandwidth_mbps;
}

// 内存写入带宽测试
double test_write_bandwidth(char *buffer, size_t size) {
    double start_time, end_time, total_time = 0;
    size_t bytes_per_iteration = size;
    
    for (int iter = 0; iter < config.iterations; iter++) {
        start_time = get_time_us();
        
        // 写入内存
        for (size_t i = 0; i < size; i += CACHE_LINE_SIZE) {
            buffer[i] = (char)(i & 0xFF);
        }
        
        end_time = get_time_us();
        total_time += (end_time - start_time);
    }
    
    double avg_time_us = total_time / config.iterations;
    double bandwidth_mbps = (bytes_per_iteration / avg_time_us) * 1000000.0 / MB;
    
    if (config.verbose) {
        printf("Write test: %zu bytes in %.2f us, bandwidth: %.2f MB/s\n", 
               bytes_per_iteration, avg_time_us, bandwidth_mbps);
    }
    
    return bandwidth_mbps;
}

// 内存复制带宽测试
double test_copy_bandwidth(char *src, char *dst, size_t size) {
    double start_time, end_time, total_time = 0;
    size_t bytes_per_iteration = size;
    
    for (int iter = 0; iter < config.iterations; iter++) {
        start_time = get_time_us();
        
        // 复制内存
        memcpy(dst, src, size);
        
        end_time = get_time_us();
        total_time += (end_time - start_time);
    }
    
    double avg_time_us = total_time / config.iterations;
    double bandwidth_mbps = (bytes_per_iteration / avg_time_us) * 1000000.0 / MB;
    
    if (config.verbose) {
        printf("Copy test: %zu bytes in %.2f us, bandwidth: %.2f MB/s\n", 
               bytes_per_iteration, avg_time_us, bandwidth_mbps);
    }
    
    return bandwidth_mbps;
}

// 内存缩放带宽测试 (dst = a * src)
double test_scale_bandwidth(float *src, float *dst, size_t size, float a) {
    double start_time, end_time, total_time = 0;
    size_t elements = size / sizeof(float);
    size_t bytes_per_iteration = size;
    
    for (int iter = 0; iter < config.iterations; iter++) {
        start_time = get_time_us();
        
        // 缩放操作
        for (size_t i = 0; i < elements; i++) {
            dst[i] = a * src[i];
        }
        
        end_time = get_time_us();
        total_time += (end_time - start_time);
    }
    
    double avg_time_us = total_time / config.iterations;
    double bandwidth_mbps = (bytes_per_iteration / avg_time_us) * 1000000.0 / MB;
    
    if (config.verbose) {
        printf("Scale test: %zu bytes in %.2f us, bandwidth: %.2f MB/s\n", 
               bytes_per_iteration, avg_time_us, bandwidth_mbps);
    }
    
    return bandwidth_mbps;
}

// 内存加法带宽测试 (dst = src1 + src2)
double test_add_bandwidth(float *src1, float *src2, float *dst, size_t size) {
    double start_time, end_time, total_time = 0;
    size_t elements = size / sizeof(float);
    size_t bytes_per_iteration = size * 2; // 读取两个源，写入一个目标
    
    for (int iter = 0; iter < config.iterations; iter++) {
        start_time = get_time_us();
        
        // 加法操作
        for (size_t i = 0; i < elements; i++) {
            dst[i] = src1[i] + src2[i];
        }
        
        end_time = get_time_us();
        total_time += (end_time - start_time);
    }
    
    double avg_time_us = total_time / config.iterations;
    double bandwidth_mbps = (bytes_per_iteration / avg_time_us) * 1000000.0 / MB;
    
    if (config.verbose) {
        printf("Add test: %zu bytes in %.2f us, bandwidth: %.2f MB/s\n", 
               bytes_per_iteration, avg_time_us, bandwidth_mbps);
    }
    
    return bandwidth_mbps;
}

// 内存三元组带宽测试 (dst = a * src1 + src2)
double test_triad_bandwidth(float *src1, float *src2, float *dst, size_t size, float a) {
    double start_time, end_time, total_time = 0;
    size_t elements = size / sizeof(float);
    size_t bytes_per_iteration = size * 2; // 读取两个源，写入一个目标
    
    for (int iter = 0; iter < config.iterations; iter++) {
        start_time = get_time_us();
        
        // 三元组操作
        for (size_t i = 0; i < elements; i++) {
            dst[i] = a * src1[i] + src2[i];
        }
        
        end_time = get_time_us();
        total_time += (end_time - start_time);
    }
    
    double avg_time_us = total_time / config.iterations;
    double bandwidth_mbps = (bytes_per_iteration / avg_time_us) * 1000000.0 / MB;
    
    if (config.verbose) {
        printf("Triad test: %zu bytes in %.2f us, bandwidth: %.2f MB/s\n", 
               bytes_per_iteration, avg_time_us, bandwidth_mbps);
    }
    
    return bandwidth_mbps;
}

// 线程函数
void* bandwidth_test_thread(void *arg) {
    int thread_id = *(int*)arg;
    set_thread_affinity(thread_id);
    
    // 分配内存
    char *buffer1 = malloc(config.buffer_size);
    char *buffer2 = malloc(config.buffer_size);
    float *float_buffer1 = (float*)buffer1;
    float *float_buffer2 = (float*)buffer2;
    float *float_buffer3 = malloc(config.buffer_size);
    
    if (!buffer1 || !buffer2 || !float_buffer3) {
        fprintf(stderr, "Failed to allocate memory for thread %d\n", thread_id);
        return NULL;
    }
    
    // 初始化数据
    for (size_t i = 0; i < config.buffer_size / sizeof(float); i++) {
        float_buffer1[i] = (float)i;
        float_buffer2[i] = (float)(i * 2);
        float_buffer3[i] = 0.0f;
    }
    
    bandwidth_result_t result;
    
    // 运行各种带宽测试
    result.read_bandwidth = test_read_bandwidth(buffer1, config.buffer_size);
    result.write_bandwidth = test_write_bandwidth(buffer2, config.buffer_size);
    result.copy_bandwidth = test_copy_bandwidth(buffer1, buffer2, config.buffer_size);
    result.scale_bandwidth = test_scale_bandwidth(float_buffer1, float_buffer3, config.buffer_size, 2.0f);
    result.add_bandwidth = test_add_bandwidth(float_buffer1, float_buffer2, float_buffer3, config.buffer_size);
    result.triad_bandwidth = test_triad_bandwidth(float_buffer1, float_buffer2, float_buffer3, config.buffer_size, 2.0f);
    
    // 返回结果
    bandwidth_result_t *thread_result = malloc(sizeof(bandwidth_result_t));
    *thread_result = result;
    
    // 清理内存
    free(buffer1);
    free(buffer2);
    free(float_buffer3);
    
    return thread_result;
}

// 打印帮助信息
void print_usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -s <size>       Buffer size in MB (default: 100)\n");
    printf("  -i <iterations> Number of iterations (default: 10)\n");
    printf("  -t <threads>    Number of threads (default: 1)\n");
    printf("  -a              Enable thread affinity\n");
    printf("  -v              Verbose output\n");
    printf("  -h              Show this help\n");
    printf("\n");
}

// 解析命令行参数
void parse_args(int argc, char *argv[]) {
    int opt;
    
    while ((opt = getopt(argc, argv, "s:i:t:avh")) != -1) {
        switch (opt) {
            case 's':
                config.buffer_size = atoi(optarg) * MB;
                break;
            case 'i':
                config.iterations = atoi(optarg);
                break;
            case 't':
                config.num_threads = atoi(optarg);
                break;
            case 'a':
                config.affinity = 1;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }
}

// 打印系统信息
void print_system_info() {
    printf("Memory Bandwidth Test\n");
    printf("=====================\n");
    printf("Buffer size: %zu MB\n", config.buffer_size / MB);
    printf("Iterations: %d\n", config.iterations);
    printf("Threads: %d\n", config.num_threads);
    printf("Thread affinity: %s\n", config.affinity ? "enabled" : "disabled");
    printf("Cache line size: %d bytes\n", CACHE_LINE_SIZE);
    printf("\n");
}

// 打印结果
void print_results(bandwidth_result_t *results, int num_threads) {
    printf("\nResults Summary:\n");
    printf("================\n");
    
    if (num_threads == 1) {
        bandwidth_result_t *result = results;
        printf("Read bandwidth:     %8.2f MB/s\n", result->read_bandwidth);
        printf("Write bandwidth:    %8.2f MB/s\n", result->write_bandwidth);
        printf("Copy bandwidth:     %8.2f MB/s\n", result->copy_bandwidth);
        printf("Scale bandwidth:    %8.2f MB/s\n", result->scale_bandwidth);
        printf("Add bandwidth:      %8.2f MB/s\n", result->add_bandwidth);
        printf("Triad bandwidth:    %8.2f MB/s\n", result->triad_bandwidth);
    } else {
        // 多线程结果
        bandwidth_result_t total = {0};
        for (int i = 0; i < num_threads; i++) {
            total.read_bandwidth += results[i].read_bandwidth;
            total.write_bandwidth += results[i].write_bandwidth;
            total.copy_bandwidth += results[i].copy_bandwidth;
            total.scale_bandwidth += results[i].scale_bandwidth;
            total.add_bandwidth += results[i].add_bandwidth;
            total.triad_bandwidth += results[i].triad_bandwidth;
        }
        
        printf("Total Read bandwidth:     %8.2f MB/s\n", total.read_bandwidth);
        printf("Total Write bandwidth:    %8.2f MB/s\n", total.write_bandwidth);
        printf("Total Copy bandwidth:     %8.2f MB/s\n", total.copy_bandwidth);
        printf("Total Scale bandwidth:    %8.2f MB/s\n", total.scale_bandwidth);
        printf("Total Add bandwidth:      %8.2f MB/s\n", total.add_bandwidth);
        printf("Total Triad bandwidth:    %8.2f MB/s\n", total.triad_bandwidth);
        
        printf("\nPer-thread results:\n");
        for (int i = 0; i < num_threads; i++) {
            printf("Thread %d: R=%.1f W=%.1f C=%.1f S=%.1f A=%.1f T=%.1f MB/s\n",
                   i, results[i].read_bandwidth, results[i].write_bandwidth,
                   results[i].copy_bandwidth, results[i].scale_bandwidth,
                   results[i].add_bandwidth, results[i].triad_bandwidth);
        }
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
    print_system_info();
    
    if (config.num_threads == 1) {
        // 单线程测试
        int thread_id = 0;
        bandwidth_result_t *result = bandwidth_test_thread(&thread_id);
        if (result) {
            print_results(result, 1);
            free(result);
        }
    } else {
        // 多线程测试
        pthread_t *threads = malloc(config.num_threads * sizeof(pthread_t));
        int *thread_ids = malloc(config.num_threads * sizeof(int));
        bandwidth_result_t *results = malloc(config.num_threads * sizeof(bandwidth_result_t));
        
        if (!threads || !thread_ids || !results) {
            fprintf(stderr, "Failed to allocate memory for threads\n");
            return 1;
        }
        
        // 创建线程
        for (int i = 0; i < config.num_threads; i++) {
            thread_ids[i] = i;
            if (pthread_create(&threads[i], NULL, bandwidth_test_thread, &thread_ids[i]) != 0) {
                perror("Failed to create thread");
                return 1;
            }
        }
        
        // 等待所有线程完成
        for (int i = 0; i < config.num_threads; i++) {
            bandwidth_result_t *thread_result;
            if (pthread_join(threads[i], (void**)&thread_result) != 0) {
                perror("Failed to join thread");
                return 1;
            }
            results[i] = *thread_result;
            free(thread_result);
        }
        
        print_results(results, config.num_threads);
        
        free(threads);
        free(thread_ids);
        free(results);
    }
    
    return 0;
} 