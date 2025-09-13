package server;

import config.SystemConfig;
import network.ServerNetworkManager;
import server.idp.IdentityProviderGroup;
import storage.RedisStorage;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 多服务器主启动类，每个服务器使用不同端口
 */
public class MultiServerMain {
    
    public static void main(String[] args) {
        System.out.println("🚀 启动多服务器阈值RSA JWT认证系统...");
        System.out.println("服务器数量: " + SystemConfig.NUM_SERVERS + ", 阈值: " + SystemConfig.THRESHOLD);
        
        try {
            // 初始化身份提供商组
            IdentityProviderGroup idpGroup = new IdentityProviderGroup();
            idpGroup.globalSetup(SystemConfig.NUM_SERVERS, SystemConfig.THRESHOLD);
            
            // 创建线程池来管理多个服务器
            ExecutorService serverPool = Executors.newFixedThreadPool(SystemConfig.NUM_SERVERS);
            List<ServerNetworkManager> servers = new ArrayList<>();
            
            // 启动多个服务器，每个使用不同端口
            for (int i = 0; i < SystemConfig.NUM_SERVERS; i++) {
                final int serverId = i;
                ServerNetworkManager serverManager = new ServerNetworkManager(idpGroup, serverId);
                servers.add(serverManager);
                
                // 在单独的线程中启动每个服务器
                serverPool.submit(() -> {
                    try {
                        serverManager.start();
                    } catch (Exception e) {
                        System.err.println("❌ 服务器 " + serverId + " 启动失败: " + e.getMessage());
                        e.printStackTrace();
                    }
                });
                
                // 给每个服务器一点启动时间
                Thread.sleep(100);
            }
            
            System.out.println("✅ 所有服务器已启动");
            System.out.println("服务器端口范围: " + (SystemConfig.BASE_PORT) + " - " + (SystemConfig.BASE_PORT + SystemConfig.NUM_SERVERS - 1));
            
            // 添加关闭钩子
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n🛑 正在关闭所有服务器...");
                for (ServerNetworkManager server : servers) {
                    server.stop();
                }
                serverPool.shutdown();
                System.out.println("✅ 所有服务器已关闭");
            }));
            
            // 保持主线程运行
            Thread.currentThread().join();
            
        } catch (Exception e) {
            System.err.println("❌ 多服务器启动失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } finally {
            RedisStorage.getInstance().close();
        }
    }
}
