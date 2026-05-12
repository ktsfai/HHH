NVCC    = nvcc
# sm_70 = V100/RTX 2080+；sm_86 = RTX 3000 系；sm_89 = RTX 4000 系
# 传入 ARCH= 可覆盖，例如：make ARCH=sm_86
ARCH    ?= sm_70
FLAGS   = -O3 -arch=$(ARCH) --std=c++14
TARGET  = hash256-cuda-worker

$(TARGET): main.cu
	$(NVCC) $(FLAGS) -o $(TARGET) main.cu

clean:
	rm -f $(TARGET)
