# 文件远程传输获取系统（客户端-服务器）
Remote file transfer and retrieval system (client server)

⚠️⚠️⚠️⚠️⚠️⚠️请勿用于违法用途，（Do not use for illegal purposes）
免责声明：本项目按“现状”提供，作者或版权所有者不对任何直接、间接、偶然、特殊或后果性损害（包括但不限于数据丢失、利润损失、业务中断等）承担任何责任，无论此类损害是因使用本软件、无法使用本项目，或与项目功能相关的其他行为所导致，也无论责任是基于合同、侵权（包括过失）或其他法律理论。您在使用、修改或分发本项目时需自行承担全部风险。作者不保证项目的适用性、安全性或无误性。您必须确保使用本软件的行为完全符合适用法律和法规。若因违反法律要求导致任何纠纷或责任，作者或版权所有者概不负责。
Disclaimer: This project is provided "as is" and the author or copyright owner shall not be liable for any direct, indirect, incidental, special, or consequential damages (including but not limited to data loss, loss of profits, business interruption, etc.), whether caused by the use of this software, inability to use this project, or other actions related to project functionality, and whether liability is based on contract, tort (including negligence), or other legal theories. You bear all risks when using, modifying, or distributing this project. The author does not guarantee the applicability, safety, or accuracy of the project. You must ensure that your use of this software fully complies with applicable laws and regulations. The author or copyright owner shall not be held responsible for any disputes or liabilities arising from violations of legal requirements.

一个基于C语言实现的跨平台文件传输系统，支持大文件传输、断点重试、设备热插拔检测等功能。客户端自动扫描指定类型文件并优先传输，服务器端接收并保存文件
（Continuously update a cross platform file transfer system based on C language, supporting functions such as large file transfer, breakpoint retry, and device hot plug detection. The client automatically scans specified types of files and prioritizes transmission, while the server receives and saves the files）

## 功能特性
（⚠️⚠️⚠️客户端静默运行无提示！）（⚠️⚠️⚠️ The client runs silently without any prompts!）
### 客户端
- 自动扫描：支持扫描USB设备、D盘及其他固定驱动器
- 文件过滤：默认支持PSD/BMP/JPG/PNG等图像格式（可扩展）
- 优先级传输：USB大文件 > USB中等文件 > 本地大文件 > 本地中等文件 > 小文件
- 断点重试：网络中断自动重连，支持指数退避策略
- 设备热插拔：实时检测U盘插拔事件
- 开机自启：自动注册系统启动项
- 日志记录：完整传输日志记录

### 服务器
- 多线程处理：支持并发连接
- 进度显示：实时显示文件接收进度
- 日志系统：记录完整传输日志
- 大文件支持：支持4GB+文件传输
- ACK确认：文件接收成功后发送确认

## 编译指南

### 环境要求
- Windows 10/11
- CMake 3.20+
- MinGW-w64（推荐GCC 12.2.0）

### 编译步骤
推荐使用clion的c11标准直接构建项目！！！！！！

客户端：
```bash
cd client/
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
cmake --build . --config Release

服务端：
cd server/
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
cmake --build . --config Release

客户端配置（main.c）
#define SERVER_IP               "服务器IP地址（Server IP Address）"
#define SERVER_PORT             9000 //服务器端口（server port）,例如9000，需要保证服务器端口可用

服务器配置（server.c）
// 定义常量
// Please match the port specified by the client
#define PORT 9000 // 服务器监听端口，请与客户端指定的端口一致！
//The received files are saved in a directory on the server, which can be specified by oneself
#define SAVE_DIR "D:\\ReceivedFiles" // 接受到的文件在服务器保存目录，可以自行指定
//Server log file path, can be specified by oneself
#define LOG_FILE "D:\\server_log.txt" // 服务器日志文件路径，可以自行指定

使用说明：
客户端
1 编译生成untitled.exe

2 首次运行自动注册开机启动

3 插入U盘自动触发扫描传输

服务器
1 编译生成FileServer.exe

2 首次运行自动创建保存目录

3 窗口化显示传输日志

4 支持最大256KB日志缓存

注意事项：
路径长度：支持最大4096字符路径（Windows API限制）

文件锁定：传输过程中请勿修改源文件

防火墙设置：需允许指定的端口通信，服务器防火墙开放指定端口

日志轮转：建议定期清理服务器日志

内存要求：服务器保存目录有足够磁盘空间