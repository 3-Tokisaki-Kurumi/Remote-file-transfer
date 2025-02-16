#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <direct.h>
#include <errno.h>
#include <process.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")  // 链接 Winsock 库

// 定义常量
// Please match the port specified by the client
#define PORT 9000 // 服务器监听端口，请与客户端指定的端口一致！

//The received files are saved in a directory on the server, which can be specified by oneself
#define SAVE_DIR "D:\\ReceivedFiles" // 接受到的文件在服务器保存目录，可以自行指定

//Server log file path, can be specified by oneself
#define LOG_FILE "D:\\server_log.txt" // 服务器日志文件路径，可以自行指定

#define BUFFER_SIZE (4 * 1024 * 1024) // 缓冲区大小（4MB）
#define PROGRESS_UPDATE_STEP 1       // 进度更新步长（每1%更新一次）

// 全局变量：窗口句柄和日志编辑控件
HWND g_hwnd;                         // 主窗口句柄
HWND g_hEditLog;                     // 日志编辑控件句柄

// 日志编辑控件最大文本长度
#define MAX_LOG_LENGTH 262144  // 256KB

// 自定义消息：更新日志
#define WM_UPDATE_LOG (WM_USER + 1) // 自定义消息，用于更新日志

// 线程参数
typedef struct {
    SOCKET client_sock;              // 客户端套接字
    SOCKADDR_IN client_addr;         // 客户端地址
    char filename[1024];             // 文件名
    int last_percent;                // 上次进度百分比
} ClientParam;

// 手动实现 long long 的字节序转换
unsigned long long htonll(unsigned long long value) {
    int num = 42;
    if (*(char *)&num == 42) { // 检查是否为小端字节序
        const unsigned int high = htonl((unsigned int)(value >> 32));
        const unsigned int low = htonl((unsigned int)(value & 0xFFFFFFFFLL));
        return (((unsigned long long)low) << 32) | high;
    } else {
        return value;
    }
}

unsigned long long ntohll(unsigned long long value) {
    return htonll(value);
}


// 日志函数（通过消息队列更新到界面）
void log_message(const char* format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    buffer[sizeof(buffer) - 1] = '\0';

    // 发送消息到主窗口更新日志
    if (g_hwnd != NULL) {
        PostMessage(g_hwnd, WM_UPDATE_LOG, 0, (LPARAM)_strdup(buffer));
    }

    // 同时写入文件
    FILE* log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        fclose(log_file);
    }

    va_end(args);
}

// 新增函数：检查并处理 INIT 通知
BOOL CheckForInitialNotification(SOCKET sock, const char* client_ip) {
    char init_buffer[64] = {0};
    int init_received = recv(sock, init_buffer, sizeof(init_buffer) - 1, MSG_PEEK); // 仅窥探数据，不移除缓冲区

    if (init_received > 0) {
        init_buffer[init_received] = '\0';
        if (strstr(init_buffer, "[INIT]") != NULL) {
            log_message("############################################################## [INIT] Client connected from [%s] ========================================================================================================================", client_ip);
            // 从缓冲区实际移除 INIT 消息
            recv(sock, init_buffer, init_received, 0);
            return TRUE;
        }
    }
    return FALSE;
}

// 发送完整数据包
int send_all(SOCKET s, const char *buf, int len) {
    int total = 0;
    while (total < len) {
        int sent = send(s, buf + total, len - total, 0);
        if (sent <= 0) return sent;
        total += sent;
    }
    return total;
}

// 客户端处理线程
unsigned __stdcall ClientHandler(void* param) {
    ClientParam* cp = (ClientParam*)param;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cp->client_addr.sin_addr, ip_str, sizeof(ip_str));

    // ---------- 新增：调用独立函数处理 INIT 通知 ----------
    if (CheckForInitialNotification(cp->client_sock, ip_str)) {
        // 注意：此处仅记录日志，不关闭连接，继续后续文件传输！
    }

    // 接收文件大小
    long long file_size = 0;
    char *file_size_ptr = (char *)&file_size;
    int bytes_remaining = sizeof(file_size);
    while (bytes_remaining > 0) {
        int bytes_received = recv(cp->client_sock, file_size_ptr, bytes_remaining, 0);
        if (bytes_received <= 0) {
            log_message("[ERROR] Failed to receive file size from %s", ip_str);
            closesocket(cp->client_sock);
            free(cp);
            return 0;
        }
        file_size_ptr += bytes_received;
        bytes_remaining -= bytes_received;
    }
    file_size = ntohll(file_size); // 网络字节序转换

    // 接收文件名长度
    int filename_len = 0;
    char *filename_len_ptr = (char*)&filename_len;
    bytes_remaining = sizeof(filename_len);
    while (bytes_remaining > 0) {
        int bytes_received = recv(cp->client_sock, filename_len_ptr, bytes_remaining, 0);
        if (bytes_received <= 0) {
            log_message("[ERROR] Failed to receive filename length from %s", ip_str);
            closesocket(cp->client_sock);
            free(cp);
            return 0;
        }
        filename_len_ptr += bytes_received;
        bytes_remaining -= bytes_received;
    }
    filename_len = ntohl(filename_len); // 转换为主机字节序

    // 接收文件名
    int name_len = 0;
    char filename[1024] = {0};
    char *filename_ptr = filename;
    while (name_len < filename_len && name_len < sizeof(filename) - 1) {
        int bytes_received = recv(cp->client_sock, filename_ptr,
                                  min(filename_len - name_len, sizeof(filename) - 1 - name_len), 0);
        if (bytes_received <= 0) {
            log_message("[ERROR] Failed to receive filename from %s", ip_str);
            closesocket(cp->client_sock);
            free(cp);
            return 0;
        }
        filename_ptr += bytes_received;
        name_len += bytes_received;
    }
    filename[name_len] = '\0'; // 手动添加终止符

    // 保存文件名到结构体
    strncpy(cp->filename, filename, sizeof(cp->filename)-1);
    cp->last_percent = -1;  // 初始化进度

    // 创建文件
    char save_path[1024];
    snprintf(save_path, sizeof(save_path), "%s\\%s", SAVE_DIR, filename);
    FILE *fp = fopen(save_path, "wb");
    if (!fp) {
        log_message("[ERROR] Failed to create file: %s", save_path);
        closesocket(cp->client_sock);
        free(cp);
        return 0;
    }

    // 接收文件内容（添加进度显示）
    long long total_bytes = 0;
    char buffer[BUFFER_SIZE];
    while (total_bytes < file_size) {
        int bytes_received = recv(cp->client_sock, buffer, min(sizeof(buffer), (size_t)(file_size - total_bytes)), 0);
        if (bytes_received <= 0) break;
        fwrite(buffer, 1, bytes_received, fp);
        total_bytes += bytes_received;

        // 计算并显示进度
        int percent = (int)((total_bytes * 100) / file_size);
        if (percent != cp->last_percent && (percent % PROGRESS_UPDATE_STEP == 0)) {
            cp->last_percent = percent;
            log_message("[PROGRESS] %s - %d%%", cp->filename, percent);
        }
    }

    fclose(fp);

    // 发送确认消息给客户端
    const char *ack_msg = "[ACK] File received successfully";
    if (send_all(cp->client_sock, ack_msg, (int)strlen(ack_msg) + 1) <= 0) {
        log_message("[WARNING] Failed to send ACK to client");
    }

    closesocket(cp->client_sock);
    log_message("[SUCCESS] Received %s (%.2f MB) from %s", filename, (double)total_bytes / (1024 * 1024), ip_str);
    free(cp);
    return 0;
}

// 服务器线程函数
unsigned __stdcall ServerThread(void* param) {
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        log_message("[ERROR] Winsock initialization failed");
        return 1;
    }

    // 创建保存目录
    if (_mkdir(SAVE_DIR) != 0 && errno != EEXIST) {
        log_message("[ERROR] Failed to create directory: %s", SAVE_DIR);
        WSACleanup();
        return 1;
    }

    // 创建监听套接字
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        log_message("[ERROR] Socket creation failed: %d", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 绑定地址
    SOCKADDR_IN addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        log_message("[ERROR] Bind failed: %d", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    // 开始监听
    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        log_message("[ERROR] Listen failed: %d", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    log_message("[INFO] Server is listening on port %d", PORT);

    // 接受客户端连接
    while (1) {
        ClientParam* cp = (ClientParam*)malloc(sizeof(ClientParam));
        int addr_len = sizeof(cp->client_addr);
        cp->client_sock = accept(listen_sock, (SOCKADDR*)&cp->client_addr, &addr_len);

        if (cp->client_sock == INVALID_SOCKET) {
            log_message("[WARNING] Accept failed, retrying...");
            free(cp);
            continue;
        }

        // 打印客户端连接信息
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cp->client_addr.sin_addr, ip_str, sizeof(ip_str));
        log_message("[CONNECT] New client connected from %s", ip_str);

        // 创建线程处理客户端
        HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ClientHandler, cp, 0, NULL);
        if (hThread == NULL) {
            log_message("[ERROR] Failed to create thread");
            closesocket(cp->client_sock);
            free(cp);
        } else {
            CloseHandle(hThread);
        }
    }

    closesocket(listen_sock);
    WSACleanup();
    return 0;
}

// 窗口消息处理函数
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // 创建日志显示编辑框（原有代码）
            g_hEditLog = CreateWindowEx(
                    WS_EX_CLIENTEDGE, "EDIT", "",
                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                    10, 10, 760, 440,
                    hwnd, NULL, GetModuleHandle(NULL), NULL
            );
            SendMessage(g_hEditLog, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
            // 设置编辑控件的文本长度限制
            SendMessage(g_hEditLog, EM_SETLIMITTEXT, MAX_LOG_LENGTH, 0);
            break;
        }
        case WM_SIZE: {
            // 窗口大小改变时调整编辑控件大小
            RECT rcClient;
            GetClientRect(hwnd, &rcClient);
            MoveWindow(g_hEditLog,
                       10,  // 左边距
                       10,  // 上边距
                       rcClient.right - 20,  // 宽度
                       rcClient.bottom - 20,  // 高度
                       TRUE);
            break;
        }
        case WM_UPDATE_LOG: {
            // 修改日志追加逻辑（保留原有逻辑，优化截断方式）
            char* log_text = (char*)lParam;
            int len = GetWindowTextLength(g_hEditLog);

            // 动态删除旧日志（保留最近内容）
            if (len + strlen(log_text) + 2 > MAX_LOG_LENGTH) {
                // 删除前1/3的文本以避免乱码
                int delete_chars = len / 3;
                SendMessage(g_hEditLog, EM_SETSEL, 0, delete_chars);
                SendMessage(g_hEditLog, EM_REPLACESEL, 0, (LPARAM)"");
            }

            // 追加新日志
            SendMessage(g_hEditLog, EM_SETSEL, len, len);
            SendMessage(g_hEditLog, EM_REPLACESEL, 0, (LPARAM)log_text);
            SendMessage(g_hEditLog, EM_REPLACESEL, 0, (LPARAM)"\r\n");
            free(log_text);
            break;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// 程序入口（WinMain）
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 注册窗口类
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "ServerWindowClass";
    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, "Window Registration Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    // 创建窗口
    g_hwnd = CreateWindowEx(
            0,
            "ServerWindowClass",
            "File Server",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 800, 500,
            NULL, NULL, hInstance, NULL
    );

    if (g_hwnd == NULL) {
        MessageBox(NULL, "Window Creation Failed!", "Error", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    // 启动服务器线程
    HANDLE hServerThread = (HANDLE)_beginthreadex(NULL, 0, ServerThread, NULL, 0, NULL);
    if (hServerThread == NULL) {
        log_message("[ERROR] Failed to start server thread");
        return 1;
    }

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CloseHandle(hServerThread);
    return (int)msg.wParam;
}