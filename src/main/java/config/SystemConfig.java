package config;

/**
 * Centralized system configuration.
 * Modify values here to change deployment parameters.
 */
public final class SystemConfig {
    private SystemConfig() {}

    // Core parameters
    public static final int NUM_SERVERS = 10;   // number of IdP servers
    public static final int THRESHOLD = 7;      // threshold t

    // Networking
    public static final String SERVER_HOST = "localhost";
    public static final String RP_HOST = "example.com";
    public static final int BASE_PORT = 9000;   // IdP servers listen on BASE_PORT + serverId (0..NUM_SERVERS-1)
    public static final int RP_SERVER_PORT = 8999; // RP server port

    // Timeouts (ms)
    public static final int CONNECTION_TIMEOUT_MS = 5000;

    // Server thread pool size
    public static final int SERVER_THREADS = 10;
    public static final int RP_SERVER_THREADS = 10;
    public static final int CONCURRENT_REQUEST_THREADS = 10;
}
