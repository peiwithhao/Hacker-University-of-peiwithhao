obj-m += pwhrootkit.o
CURRENT_PATH := $(shell pwd)
# KERNEL_VERSION := $(shell uname -r)
MAIN_DIR := /home/$(shell whoami)
KERNEL_SOURCE_DIR := $(MAIN_DIR)/Kernel/kernel_source/linux-6.3.4/

BUILD_DIR := $(CURRENT_PATH)/build


all:
	mkdir -p $(BUILD_DIR)  # 确保构建目录存在
	make -C $(KERNEL_SOURCE_DIR) M=$(CURRENT_PATH) O=$(BUILD_DIR) modules
clean:
	make -C $(KERNEL_SOURCE_DIR) M=$(CURRENT_PATH) O=$(BUILD_DIR) clean
