package storage;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import utils.CryptoUtil;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Redis存储模块，用于替代文件存储
 */
public class RedisStorage {
    private static RedisStorage instance;
    private JedisPool jedisPool;
    private final String REDIS_HOST = "localhost";
    private final int REDIS_PORT = 6379;
    private final int REDIS_DATABASE = 0;
    
    // 键名前缀
    private static final String USER_DATA_PREFIX = "user_data:";
    private static final String SERVER_KEYS_PREFIX = "server_keys:";
    private static final String RP_CERT_PREFIX = "rp_cert:";
    private static final String THRESHOLD_KEYS_PREFIX = "threshold_keys:";
    private static final String CLIENT_DATA_PREFIX = "client_data:";
    private static final String RP_STATE_PREFIX = "rp_state:";
    
    private RedisStorage() {
        initializeRedis();
        // ==================== 新增修改点 ====================
        // 注册一个JVM关闭钩子。当程序退出时，这个钩子会被自动调用。
        // 这样可以确保无论如何，连接池都会被优雅地关闭。
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
        // ==================================================
    }
    
    public static synchronized RedisStorage getInstance() {
        if (instance == null) {
            instance = new RedisStorage();
        }
        return instance;
    }
    
    private void initializeRedis() {
        try {
            JedisPoolConfig config = new JedisPoolConfig();
            config.setMaxTotal(20);
            config.setMaxIdle(10);
            config.setMinIdle(5);
            config.setTestOnBorrow(false);
            config.setTestOnReturn(true);
            config.setTestWhileIdle(true);
            
            this.jedisPool = new JedisPool(config, REDIS_HOST, REDIS_PORT, 2000, null, REDIS_DATABASE);
            System.out.println("✅ Redis连接池初始化成功");
        } catch (Exception e) {
            System.err.println("❌ Redis连接失败: " + e.getMessage());
            throw new RuntimeException("Failed to initialize Redis", e);
        }
    }
    
    /**
     * 存储用户数据到Redis
     */
    public void storeUserData(int serverId, byte[] lookupKey, byte[] symmetricKey) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = USER_DATA_PREFIX + serverId + ":" + CryptoUtil.bytesToHex(lookupKey);
            String value = CryptoUtil.bytesToHex(symmetricKey);
            jedis.set(key, value);
            System.out.println("✅ 用户数据已存储到Redis: " + key);
        } catch (Exception e) {
            System.err.println("❌ 存储用户数据失败: " + e.getMessage());
            throw new RuntimeException("Failed to store user data", e);
        }
    }
    
    /**
     * 从Redis检索用户数据
     */
    public byte[] retrieveUserData(int serverId, byte[] lookupKey) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = USER_DATA_PREFIX + serverId + ":" + CryptoUtil.bytesToHex(lookupKey);
            String value = jedis.get(key);
            if (value != null) {
                return CryptoUtil.hexToBytes(value);
            }
            return null;
        } catch (Exception e) {
            System.err.println("❌ 检索用户数据失败: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 存储服务器密钥份额
     */
    public void storeServerKeyShare(int serverId, String keyType, String value) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = SERVER_KEYS_PREFIX + serverId + ":" + keyType;
            jedis.set(key, value);
            System.out.println("✅ 服务器密钥已存储到Redis: " + key);
        } catch (Exception e) {
            System.err.println("❌ 存储服务器密钥失败: " + e.getMessage());
            throw new RuntimeException("Failed to store server key", e);
        }
    }
    
    /**
     * 检索服务器密钥份额
     */
    public String retrieveServerKeyShare(int serverId, String keyType) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = SERVER_KEYS_PREFIX + serverId + ":" + keyType;
            return jedis.get(key);
        } catch (Exception e) {
            System.err.println("❌ 检索服务器密钥失败: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 存储RP证书
     */
    public void storeRPCertificate(String rpId, String identityHex, String signatureHex) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = RP_CERT_PREFIX + rpId;
            jedis.hset(key, "identity", identityHex);
            jedis.hset(key, "signature", signatureHex);
            System.out.println("✅ RP证书已存储到Redis: " + key);
        } catch (Exception e) {
            System.err.println("❌ 存储RP证书失败: " + e.getMessage());
            throw new RuntimeException("Failed to store RP certificate", e);
        }
    }
    
    /**
     * 检索RP证书
     */
    public Map<String, String> retrieveRPCertificate(String rpId) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = RP_CERT_PREFIX + rpId;
            return jedis.hgetAll(key);
        } catch (Exception e) {
            System.err.println("❌ 检索RP证书失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 存储RP的公共信息（identity、signature、公钥）
     */
    public void storeRPState(String rpId, String identityHex, String signatureHex, String publicKeyBase64) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = RP_STATE_PREFIX + rpId;
            if (identityHex != null) jedis.hset(key, "identity", identityHex);
            if (signatureHex != null) jedis.hset(key, "signature", signatureHex);
            if (publicKeyBase64 != null) jedis.hset(key, "publicKey", publicKeyBase64);
            System.out.println("✅ RP状态已存储到Redis: " + key);
        } catch (Exception e) {
            System.err.println("❌ 存储RP状态失败: " + e.getMessage());
            throw new RuntimeException("Failed to store RP state", e);
        }
    }

    /**
     * 存储RP的公共信息（identity、signature、公钥、rpHost）
     */
    public void storeRPState(String rpId, String identityHex, String signatureHex, String publicKeyBase64, String rpHost) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = RP_STATE_PREFIX + rpId;
            if (identityHex != null) jedis.hset(key, "identity", identityHex);
            if (signatureHex != null) jedis.hset(key, "signature", signatureHex);
            if (publicKeyBase64 != null) jedis.hset(key, "publicKey", publicKeyBase64);
            if (rpHost != null) jedis.hset(key, "rpHost", rpHost);
            System.out.println("✅ RP状态已存储到Redis: " + key);
        } catch (Exception e) {
            System.err.println("❌ 存储RP状态失败: " + e.getMessage());
            throw new RuntimeException("Failed to store RP state", e);
        }
    }

    public Map<String, String> retrieveRPState(String rpId) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = RP_STATE_PREFIX + rpId;
            return jedis.hgetAll(key);
        } catch (Exception e) {
            System.err.println("❌ 检索RP状态失败: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 存储阈值RSA密钥
     */
    public void storeThresholdKeys(Map<String, String> keyData) {
        try (Jedis jedis = jedisPool.getResource()) {
            for (Map.Entry<String, String> entry : keyData.entrySet()) {
                String key = THRESHOLD_KEYS_PREFIX + entry.getKey();
                jedis.set(key, entry.getValue());
            }
            System.out.println("✅ 阈值RSA密钥已存储到Redis");
        } catch (Exception e) {
            System.err.println("❌ 存储阈值RSA密钥失败: " + e.getMessage());
            throw new RuntimeException("Failed to store threshold keys", e);
        }
    }
    
    /**
     * 检索阈值RSA密钥
     */
    public Map<String, String> retrieveThresholdKeys() {
        try (Jedis jedis = jedisPool.getResource()) {
            Set<String> keys = jedis.keys(THRESHOLD_KEYS_PREFIX + "*");
            Map<String, String> result = new ConcurrentHashMap<>();
            
            for (String key : keys) {
                String shortKey = key.substring(THRESHOLD_KEYS_PREFIX.length());
                String value = jedis.get(key);
                result.put(shortKey, value);
            }
            return result;
        } catch (Exception e) {
            System.err.println("❌ 检索阈值RSA密钥失败: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 清理所有数据（用于测试）
     */
    public void clearAllData() {
        try (Jedis jedis = jedisPool.getResource()) {
            jedis.flushDB();
            System.out.println("✅ Redis数据库已清空");
        } catch (Exception e) {
            System.err.println("❌ 清空Redis数据库失败: " + e.getMessage());
        }
    }
    
    /**
     * 存储客户端数据
     */
    public void storeClientData(String key, String value) {
        try (Jedis jedis = jedisPool.getResource()) {
            String fullKey = CLIENT_DATA_PREFIX + key;
            jedis.set(fullKey, value);
            System.out.println("✅ 客户端数据已存储到Redis: " + fullKey);
        } catch (Exception e) {
            System.err.println("❌ 存储客户端数据失败: " + e.getMessage());
            throw new RuntimeException("Failed to store client data", e);
        }
    }
    
    /**
     * 检索客户端数据
     */
    public String retrieveClientData(String key) {
        try (Jedis jedis = jedisPool.getResource()) {
            String fullKey = CLIENT_DATA_PREFIX + key;
            return jedis.get(fullKey);
        } catch (Exception e) {
            System.err.println("❌ 检索客户端数据失败: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 关闭Redis连接池
     */
    public void close() {
        if (jedisPool != null && !jedisPool.isClosed()) {
            jedisPool.close();
            System.out.println("✅ Redis连接池已关闭");
        }
    }

    public void shutdown() {
        if (jedisPool != null && !jedisPool.isClosed()) {
            System.out.println("🔌 正在关闭Redis连接池...");
            jedisPool.close();
            System.out.println("✅ Redis连接池已成功关闭");
        }
    }
}
