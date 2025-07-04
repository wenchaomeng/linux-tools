#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <math.h>
#include <errno.h>
#include <getopt.h>

#define MB (1024 * 1024)
#define GB (1024 * MB)
#define DEFAULT_SIZE (100 * MB)
#define DEFAULT_TARGET_BANDWIDTH (1.0) // 1 GB/s
#define CACHE_LINE_SIZE 64

// 测试配置
typedef struct {
    size_t buffer_size;
    double target_bandwidth_gbps;  // 目标带宽 (GB/s)
    int duration_seconds;          // 测试持续时间
    int verbose;
    int use_memcpy;               // 是否使用memcpy
    int chunk_size;               // 每次复制的块大小
} test_config_t;

// 测试结果
typedef struct {
    double actual_bandwidth_gbps;
    double total_bytes_copied;
    double total_time_seconds;
    int iterations;
    double avg_latency_ms;
} copy_result_t;

// 全局配置
test_config_t config = {
    .buffer_size = DEFAULT_SIZE,
    .target_bandwidth_gbps = DEFAULT_TARGET_BANDWIDTH,
    .duration_seconds = 10,
    .verbose = 0,
    .use_memcpy = 1,
    .chunk_size = 64 * 1024  // 64KB chunks
};

// 获取当前时间（微秒）
static inline double get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

// 获取当前时间（秒）
static inline double get_time_s() {
    return get_time_us() / 1000000.0;
}

// 计算需要等待的时间以达到目标带宽
static inline double calculate_delay(double bytes_copied, double target_bandwidth_gbps) {
    double target_bytes_per_second = target_bandwidth_gbps * GB;
    double target_time = bytes_copied / target_bytes_per_second;
    return target_time;
}

// 手动复制函数（避免编译器优化）
void manual_copy(char *dst, const char *src, size_t size) {
    for (size_t i = 0; i < size; i += CACHE_LINE_SIZE) {
        size_t copy_size = (i + CACHE_LINE_SIZE <= size) ? CACHE_LINE_SIZE : (size - i);
        memcpy(dst + i, src + i, copy_size);
    }
}

// 以指定带宽进行复制测试
copy_result_t controlled_copy_test(char *src, char *dst, size_t total_size) {
    copy_result_t result = {0};
    double start_time = get_time_s();
    double target_bytes_per_second = config.target_bandwidth_gbps * GB;
    double bytes_per_chunk = config.chunk_size;
    double target_time_per_chunk = bytes_per_chunk / target_bytes_per_second;
    
    size_t total_chunks = total_size / config.chunk_size;
    size_t remaining_bytes = total_size % config.chunk_size;
    
    if (config.verbose) {
        printf("Target bandwidth: %.2f GB/s\n", config.target_bandwidth_gbps);
        printf("Chunk size: %d bytes\n", config.chunk_size);
        printf("Target time per chunk: %.6f seconds\n", target_time_per_chunk);
        printf("Total chunks: %zu\n", total_chunks);
    }
    
    // 复制完整块
    for (size_t chunk = 0; chunk < total_chunks; chunk++) {
        double chunk_start = get_time_s();
        
        // 执行复制
        if (config.use_memcpy) {
            memcpy(dst + chunk * config.chunk_size, 
                   src + chunk * config.chunk_size, 
                   config.chunk_size);
        } else {
            manual_copy(dst + chunk * config.chunk_size, 
                       src + chunk * config.chunk_size, 
                       config.chunk_size);
        }
        
        double chunk_end = get_time_s();
        double actual_time = chunk_end - chunk_start;
        double target_time = target_time_per_chunk;
        
        // 计算需要等待的时间
        if (actual_time < target_time) {
            double sleep_time = target_time - actual_time;
            usleep((unsigned int)(sleep_time * 1000000));
        }
        
        result.total_bytes_copied += bytes_per_chunk;
        result.iterations++;
    }
    
    // 复制剩余字节
    if (remaining_bytes > 0) {
        if (config.use_memcpy) {
            memcpy(dst + total_chunks * config.chunk_size, 
                   src + total_chunks * config.chunk_size, 
                   remaining_bytes);
        } else {
            manual_copy(dst + total_chunks * config.chunk_size, 
                       src + total_chunks * config.chunk_size, 
                       remaining_bytes);
        }
        result.total_bytes_copied += remaining_bytes;
    }
    
    double end_time = get_time_s();
    result.total_time_seconds = end_time - start_time;
    result.actual_bandwidth_gbps = (result.total_bytes_copied / result.total_time_seconds) / GB;
    result.avg_latency_ms = (result.total_time_seconds / result.iterations) * 1000.0;
    
    return result;
}

// 持续复制测试（运行指定时间）
copy_result_t continuous_copy_test(char *src, char *dst, size_t buffer_size) {
    copy_result_t result = {0};
    double start_time = get_time_s();
    double target_bytes_per_second = config.target_bandwidth_gbps * GB;
    double target_time_per_buffer = buffer_size / target_bytes_per_second;
    double next_target_time = start_time + target_time_per_buffer;
    
    if (config.verbose) {
        printf("Starting continuous copy test for %d seconds...\n", config.duration_seconds);
        printf("Target bandwidth: %.2f GB/s\n", config.target_bandwidth_gbps);
        printf("Target time per buffer: %.6f seconds\n", target_time_per_buffer);
    }
    
    while ((get_time_s() - start_time) < config.duration_seconds) {
        // 执行复制
        if (config.use_memcpy) {
            memcpy(dst, src, buffer_size);
        } else {
            manual_copy(dst, src, buffer_size);
        }
        
        result.total_bytes_copied += buffer_size;
        result.iterations++;
        
        // 等待到下一个目标时间点
        double wait_until = next_target_time;
        next_target_time += target_time_per_buffer;
        
        double current_time_after_copy = get_time_s();
        if (current_time_after_copy < wait_until) {
            double sleep_time = wait_until - current_time_after_copy;
            if (sleep_time > 0) {
                usleep((unsigned int)(sleep_time * 1000000));
            }
        }
    }
    
    double end_time = get_time_s();
    result.total_time_seconds = end_time - start_time;
    result.actual_bandwidth_gbps = (result.total_bytes_copied / result.total_time_seconds) / GB;
    result.avg_latency_ms = (result.total_time_seconds / result.iterations) * 1000.0;
    
    return result;
}

// 验证复制结果
int verify_copy(char *src, char *dst, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (src[i] != dst[i]) {
            printf("Copy verification failed at position %zu: src[%zu]=%d, dst[%zu]=%d\n", 
                   i, i, (int)src[i], i, (int)dst[i]);
            return 0;
        }
    }
    return 1;
}

// 打印帮助信息
void print_usage(const char *program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -s <size>       Buffer size in MB (default: 100)\n");
    printf("  -b <bandwidth>  Target bandwidth in GB/s (default: 1.0)\n");
    printf("  -d <duration>   Test duration in seconds (default: 10)\n");
    printf("  -c <chunk>      Chunk size in KB (default: 64)\n");
    printf("  -m              Use manual copy instead of memcpy\n");
    printf("  -v              Verbose output\n");
    printf("  -h              Show this help\n");
    printf("\n");
}

// 解析命令行参数
void parse_args(int argc, char *argv[]) {
    int opt;
    
    while ((opt = getopt(argc, argv, "s:b:d:c:mvh")) != -1) {
        switch (opt) {
            case 's':
                config.buffer_size = atoi(optarg) * MB;
                break;
            case 'b':
                config.target_bandwidth_gbps = atof(optarg);
                break;
            case 'd':
                config.duration_seconds = atoi(optarg);
                break;
            case 'c':
                config.chunk_size = atoi(optarg) * 1024;
                break;
            case 'm':
                config.use_memcpy = 0;
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
    printf("Controlled Memory Copy Test\n");
    printf("==========================\n");
    printf("Buffer size: %zu MB\n", config.buffer_size / MB);
    printf("Target bandwidth: %.2f GB/s\n", config.target_bandwidth_gbps);
    printf("Test duration: %d seconds\n", config.duration_seconds);
    printf("Chunk size: %d bytes\n", config.chunk_size);
    printf("Copy method: %s\n", config.use_memcpy ? "memcpy" : "manual");
    printf("Cache line size: %d bytes\n", CACHE_LINE_SIZE);
    printf("\n");
}

// 打印结果
void print_results(const copy_result_t *result) {
    printf("\nTest Results:\n");
    printf("=============\n");
    printf("Total bytes copied: %.0f bytes (%.2f MB)\n", 
           result->total_bytes_copied, result->total_bytes_copied / MB);
    printf("Total time: %.3f seconds\n", result->total_time_seconds);
    printf("Actual bandwidth: %.3f GB/s\n", result->actual_bandwidth_gbps);
    printf("Target bandwidth: %.3f GB/s\n", config.target_bandwidth_gbps);
    printf("Bandwidth accuracy: %.2f%%\n", 
           (result->actual_bandwidth_gbps / config.target_bandwidth_gbps) * 100.0);
    printf("Iterations: %d\n", result->iterations);
    printf("Average latency: %.3f ms\n", result->avg_latency_ms);
    printf("Bytes per iteration: %.0f\n", result->total_bytes_copied / result->iterations);
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
    print_system_info();
    
    // 分配内存
    char *src_buffer = malloc(config.buffer_size);
    char *dst_buffer = malloc(config.buffer_size);
    
    if (!src_buffer || !dst_buffer) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    
    // 初始化源缓冲区
    printf("Initializing source buffer...\n");
    for (size_t i = 0; i < config.buffer_size; i++) {
        src_buffer[i] = (char)(i & 0xFF);
    }
    
    // 清空目标缓冲区
    memset(dst_buffer, 0, config.buffer_size);
    
    // 执行复制测试
    printf("Starting copy test...\n");
    copy_result_t result = continuous_copy_test(src_buffer, dst_buffer, config.buffer_size);
    
    // 验证复制结果
    printf("Verifying copy results...\n");
    if (verify_copy(src_buffer, dst_buffer, config.buffer_size)) {
        printf("Copy verification: PASSED\n");
    } else {
        printf("Copy verification: FAILED\n");
    }
    
    // 打印结果
    print_results(&result);
    
    // 清理内存
    free(src_buffer);
    free(dst_buffer);
    
    return 0;
} 