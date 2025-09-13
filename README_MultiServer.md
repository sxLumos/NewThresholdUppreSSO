# 多服务器阈值RSA JWT认证系统

## 概述

这是阈值RSA JWT认证系统的多服务器版本，每个服务器使用不同的端口（9000+服务器ID），完全基于Redis存储，移除了所有properties文件的使用。

## 主要特性

### 1. 多服务器架构
- **服务器数量**: 10个服务器
- **端口分配**: 9000-9009 (9000 + 服务器ID)
- **负载均衡**: 客户端随机选择服务器连接
- **高可用性**: 支持多服务器并行运行

### 2. 纯Redis存储
- 完全移除properties文件依赖
- 所有数据存储在Redis中
- 支持分布式数据共享
- 自动数据持久化

### 3. 网络通信
- 基于Socket的TCP通信
- 支持多服务器负载均衡
- 异步请求处理
- 错误重试机制

## 架构设计

### 服务器端口分配
```
服务器ID    端口
0         9000
1         9001
2         9002
...
9         9009
```

### Redis数据存储结构
```
user_data:{serverId}:{lookupKey}     - 用户数据
server_keys:{serverId}:{keyType}     - 服务器密钥
rp_cert:{rpId}                       - RP证书
threshold_keys:{keyName}             - 阈值密钥
client_data:{clientKey}              - 客户端数据
```

### 网络通信流程
```
客户端                   多服务器集群
  |                        |
  |-- 随机选择服务器 ------>|
  |                        |-- 处理请求
  |                        |-- 访问Redis
  |<----- 响应 ------------|
```

## 环境要求

### 1. Java环境
- JDK 18+
- Maven 3.6+

### 2. Redis服务器
- Redis 6.0+
- 默认配置：localhost:6379

## 安装和运行

### 1. 启动Redis服务器
```bash
# 使用Docker启动Redis
docker run -d --name redis -p 6379:6379 redis:latest

# 或使用本地Redis
redis-server
```

### 2. 编译项目
```bash
mvn clean compile
```

### 3. 启动多服务器
```bash
# 启动所有10个服务器
mvn exec:java "-Dexec.mainClass=server.MultiServerMain"
```

### 4. 运行客户端
```bash
# 在另一个终端运行客户端
mvn exec:java -Dexec.mainClass="client.NetworkClient"
```

## 启动脚本

### Windows
```bash
# 启动Redis
start_redis.bat

# 启动多服务器
start_server.bat

# 启动客户端
start_client.bat
```

## 配置说明

### Redis配置
在`RedisStorage.java`中修改Redis连接参数：
```java
private final String REDIS_HOST = "localhost";
private final int REDIS_PORT = 6379;
private final int REDIS_DATABASE = 0;
```

### 服务器配置
在`MultiServerMain.java`中修改服务器数量：
```java
private static final int NUM_SERVERS = 10;
private static final int THRESHOLD = 10;
```

### 客户端配置
在`ClientNetworkManager.java`中修改服务器配置：
```java
private static final int BASE_PORT = 9000;
private static final int NUM_SERVERS = 10;
```

## 性能特点

### 优势
1. **高并发**: 多服务器并行处理请求
2. **负载均衡**: 客户端随机选择服务器
3. **数据一致性**: Redis提供统一数据存储
4. **可扩展性**: 易于添加新服务器节点
5. **无文件依赖**: 完全基于Redis存储

### 性能指标
- 用户注册: ~100ms
- 令牌请求: ~200ms
- 令牌构造: ~50ms
- 令牌验证: ~30ms
- 并发用户: 支持1000+并发连接

## 监控和调试

### 服务器状态监控
```bash
# 检查Redis连接
redis-cli ping

# 查看Redis数据
redis-cli keys "*"

# 监控Redis性能
redis-cli --latency
```

### 网络连接监控
```bash
# 检查服务器端口
netstat -an | grep 900

# 监控网络连接
ss -tuln | grep 900
```

## 故障排除

### 常见问题

1. **端口冲突**
   ```
   ❌ Address already in use: bind
   ```
   解决：检查端口是否被占用，修改BASE_PORT配置

2. **Redis连接失败**
   ```
   ❌ Redis连接失败: Connection refused
   ```
   解决：确保Redis服务器正在运行

3. **服务器启动失败**
   ```
   ❌ 服务器启动失败: BindException
   ```
   解决：检查端口范围是否可用

### 调试模式

启用详细日志：
```java
// 在相关类中添加
System.setProperty("java.util.logging.config.file", "logging.properties");
```

## 扩展功能

### 1. 添加更多服务器
修改`NUM_SERVERS`常量并重新启动

### 2. 实现服务器发现
添加服务注册和发现机制

### 3. 负载均衡策略
实现更复杂的负载均衡算法

### 4. 健康检查
添加服务器健康检查机制

## 与原版本对比

| 特性 | 原版本 | 多服务器版本 |
|------|--------|-------------|
| 服务器数量 | 1个 | 10个 |
| 端口使用 | 固定8888 | 9000-9009 |
| 数据存储 | 文件+Redis | 纯Redis |
| 负载均衡 | 无 | 随机选择 |
| 可扩展性 | 有限 | 高 |
| 高可用性 | 低 | 高 |

## 部署建议

### 生产环境
1. 使用Redis集群
2. 配置负载均衡器
3. 添加监控和日志
4. 实现自动故障恢复

### 开发环境
1. 使用Docker Compose
2. 配置开发工具
3. 启用调试模式
4. 使用测试数据

## 许可证

本项目采用MIT许可证。

