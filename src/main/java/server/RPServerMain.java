package server;

import config.SystemConfig;
import network.RPServerNetworkManager;
import storage.RedisStorage;

/**
 * RP服务器主启动类
 */
public class RPServerMain {
    public static void main(String[] args) {
        System.out.println("🚀 启动RP服务器...");
        System.out.println("RP服务器端口: " + SystemConfig.RP_SERVER_PORT);
        
        try {
            // 启动RP网络管理器
            RPServerNetworkManager rpNetworkManager = new RPServerNetworkManager();
            
            // 添加关闭钩子
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nShutting down RP server..."); // 使用纯文本
                rpNetworkManager.stop();
                System.out.println("RP server stopped."); // 使用纯文本
            }));
            
            // 启动RP服务器
            rpNetworkManager.start();
            
        } catch (Exception e) {
            System.err.println("❌ RP服务器启动失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } finally {
            RedisStorage.getInstance().close();
        }
    }
}
