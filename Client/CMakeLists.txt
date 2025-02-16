cmake_minimum_required(VERSION 3.24)
project(untitled C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
# 设置 64 位编译
set(CMAKE_GENERATOR_PLATFORM x64)
add_compile_definitions(_WIN32_WINNT=0x0A00)  # 目标 Windows 10

# 启用大文件支持（64位文件操作）
add_compile_definitions(_FILE_OFFSET_BITS=64)
add_compile_definitions(_LARGE_FILES)

# 生成资源文件
add_custom_command(
        OUTPUT untitled.res
        COMMAND windres -i "${CMAKE_SOURCE_DIR}/untitled.rc" -o "${CMAKE_CURRENT_BINARY_DIR}/untitled.res"
        DEPENDS "${CMAKE_SOURCE_DIR}/untitled.rc" "${CMAKE_SOURCE_DIR}/untitled.manifest"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)



# 添加可执行文件并链接资源（使用 WIN32 子系统）
add_executable(untitled WIN32 main.c untitled.res main.c)
target_link_libraries(untitled
        ws2_32
        user32
        ole32
        )

# 禁用调试信息以减小体积（可选）
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(/Os /GL)
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG /OPT:REF /OPT:ICF")
endif()

# 设置静态链接和栈大小
set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++ -Wl,--stack,8388608"
        )

set_target_properties(untitled PROPERTIES
        LINK_FLAGS "-Wl,--subsystem,windows"
        )

# Release 模式优化
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(/Ox /GL)
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG /OPT:REF /OPT:ICF")
endif()