CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_GNU_SOURCE
LDFLAGS = -lm -lpthread

TARGETS = bandwidth_test controlled_copy_test
SOURCES = bandwidth_test.c controlled_copy_test.c

.PHONY: all clean

all: $(TARGETS)

bandwidth_test: bandwidth_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

controlled_copy_test: controlled_copy_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

# 运行示例
run-bandwidth: bandwidth_test
	./bandwidth_test -s 100 -i 5 -t 1 -v

run-controlled: controlled_copy_test
	./controlled_copy_test -s 100 -b 1.0 -d 10 -v

# 不同带宽测试
test-1gbps: controlled_copy_test
	./controlled_copy_test -s 100 -b 1.0 -d 5 -v

test-500mbps: controlled_copy_test
	./controlled_copy_test -s 100 -b 0.5 -d 5 -v

test-2gbps: controlled_copy_test
	./controlled_copy_test -s 100 -b 2.0 -d 5 -v

# 调试版本
debug: CFLAGS += -g -DDEBUG
debug: $(TARGETS)

# 优化版本
release: CFLAGS += -O3 -march=native
release: $(TARGETS)

# 安装
install: $(TARGETS)
	cp $(TARGETS) /usr/local/bin/

# 卸载
uninstall:
	rm -f /usr/local/bin/$(TARGETS)

# 帮助
help:
	@echo "Available targets:"
	@echo "  all       - Build the bandwidth test program"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build with maximum optimization"
	@echo "  clean     - Remove built files"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  run-bandwidth - Run bandwidth test"
	@echo "  run-controlled - Run controlled copy test"
	@echo "  test-1gbps - Run 1 Gbps test"
	@echo "  test-500mbps - Run 500 Mbps test"
	@echo "  test-2gbps - Run 2 Gbps test"
	@echo "  help      - Show this help"

.PHONY: all debug release clean install uninstall help 