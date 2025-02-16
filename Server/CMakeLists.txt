cmake_minimum_required(VERSION 3.20)  # 最低 CMake 版本
project(FileServer)                   # 项目名称

set(CMAKE_C_STANDARD 11)              # 使用 C11 标准

# 添加可执行文件
add_executable(FileServer server.c)

# Windows 平台专用配置
if (WIN32)
    # 使用 MinGW 隐藏控制台窗口
    target_link_options(FileServer PRIVATE -mwindows)
endif()

# 链接 Winsock 库
target_link_libraries(FileServer ws2_32)