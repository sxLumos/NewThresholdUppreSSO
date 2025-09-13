package uppresso;

/**
 * Entry point to start UppreSSO RP as a standalone server, similar to RPServerMain.
 */
public class UppreSSORPMain {
    public static void main(String[] args) {
        System.out.println("🚀 启动UppreSSO RP服务器...");
        UppreSSORP rp = new UppreSSORP();
        try {
            // ensure RP is registered with IdP
            rp.registerOverNetwork();
            // start RP server
            rp.startServer();
            // shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nShutting down UppreSSO RP server...");
                try { rp.stopServer(); } catch (Exception ignore) {}
                System.out.println("UppreSSO RP server stopped.");
            }));

            // keep main alive
            Thread.currentThread().join();
        } catch (Exception e) {
            System.err.println("❌ UppreSSO RP服务器启动失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}


