package uppresso;

/**
 * Entry point to start UppreSSO IdP as a standalone server.
 */
public class UppreSSOIdPMain {
    public static void main(String[] args) {
        System.out.println("🚀 启动UppreSSO IdP服务器...");
        UppreSSOIdP idp = new UppreSSOIdP();
        try {
            idp.startServer();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nShutting down UppreSSO IdP server...");
                try { idp.stopServer(); } catch (Exception ignore) {}
                System.out.println("UppreSSO IdP server stopped.");
            }));

            Thread.currentThread().join();
        } catch (Exception e) {
            System.err.println("❌ UppreSSO IdP服务器启动失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}


