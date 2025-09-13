package uppresso;

import utils.SimpleBenchmark;

/**
 * Entry point to start UppreSSO RP as a standalone server, similar to RPServerMain.
 */
public class UppreSSORPMain {
    private static final int benchmarkRuns = 10;
    public static void main(String[] args) {
        System.out.println("🚀 启动UppreSSO RP服务器...");
        UppreSSORP rp = new UppreSSORP();
        try {
            // start RP server
            rp.startServer();

            // --- Benchmark RP Registration with Communication Cost Measurement ---

            // 1. Reset counters before the benchmark
            rp.resetCommunicationCounters();

            // 2. Run the benchmark
            Runnable rpRegisterTask = rp::registerOverNetwork;
            double registrationTime = SimpleBenchmark.getAverageTime(benchmarkRuns, rpRegisterTask);
            System.out.printf("RP注册耗时: %.0f ms\n", registrationTime);

            // 3. Report the average communication cost
            long totalSent = rp.getTotalBytesSent();
            long totalReceived = rp.getTotalBytesReceived();
            double avgSentKB = (double) totalSent / benchmarkRuns / 1024.0;
            double avgReceivedKB = (double) totalReceived / benchmarkRuns / 1024.0;

            System.out.printf(
                    "[RP注册] 通信代价 (平均每次):\n" +
                            "  - 发送: %.2f KB\n" +
                            "  - 接收: %.2f KB\n" +
                            "  - 总计: %.2f KB\n\n",
                    avgSentKB,
                    avgReceivedKB,
                    avgSentKB + avgReceivedKB
            );
            // --- End of Benchmark ---


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