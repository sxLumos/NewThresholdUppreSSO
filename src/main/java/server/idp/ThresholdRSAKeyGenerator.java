package server.idp;

import server.interfaces.KeyGenerator;
import storage.RedisStorage;
import utils.Pair;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class ThresholdRSAKeyGenerator implements KeyGenerator {
    private BigInteger n; // RSA Modulus
    private BigInteger e; // RSA Public Exponent
    private BigInteger d; // RSA Master Private Exponent
    private List<Pair<Integer, BigInteger>> privateKeyShares;
    private int numOfServer;
    private int threshold;
    private static final int KEY_SIZE = 2048;
    public static final String PRIVATE_KEY_SHARE = "privateKeyShare";
    public static final String PUBLIC_KEY = "n";
    private final RedisStorage redisStorage;

    // 1≤threshold≤numOfServer and threshold>(numOfServer/2)
    public ThresholdRSAKeyGenerator(int numOfServer, int threshold, boolean createNewKey) {
//        if (threshold >= 1 && threshold <= numOfServer && threshold > (numOfServer / 2)) {
        if (threshold >= 1 && threshold <= numOfServer) {
            this.numOfServer = numOfServer;
            this.threshold = threshold;
            this.redisStorage = RedisStorage.getInstance();

            // 只从Redis加载，如果Redis中没有则生成新密钥
            if (!loadKeyFromRedis()) {
                if (createNewKey) {
                    System.out.println("▶️ Generating new threshold keys...");
                    this.generateKey();
                } else {
                    System.out.println("▶️ No existing keys found in Redis, generating new keys...");
                    this.generateKey();
                }
            }
        } else {
            throw new IllegalArgumentException("Threshold and numOfServer do not meet requirement.");
        }
    }

    public void generateKey() {
        SecureRandom random = new SecureRandom();

        // 1. Generate RSA parameters (p, q, n, e, d, lambda)
        BigInteger p = new BigInteger(KEY_SIZE / 2, 100, random);
        BigInteger q = new BigInteger(KEY_SIZE / 2, 100, random);
        this.n = p.multiply(q);

        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        BigInteger lambda = pMinus1.multiply(qMinus1).divide(pMinus1.gcd(qMinus1)); // lambda(n) = lcm(p-1, q-1)

        this.e = new BigInteger("65537"); // Common public exponent
        this.d = e.modInverse(lambda);

        // 2. Create a polynomial P(x) of degree threshold-1 over Z_lambda
        // P(x) = d + a1*x + a2*x^2 + ...
        BigInteger[] coefficients = new BigInteger[this.threshold];
        coefficients[0] = d; // P(0) = d
        for (int i = 1; i < this.threshold; i++) {
            coefficients[i] = new BigInteger(lambda.bitLength(), random).mod(lambda);
        }
        this.privateKeyShares = new ArrayList<>();
        for (int i = 1; i <= this.numOfServer; i++) {
            BigInteger xi = BigInteger.valueOf(i);
            BigInteger share = BigInteger.ZERO;
            // Evaluate P(i) mod lambda
            for (int j = 0; j < this.threshold; j++) {
                BigInteger term = coefficients[j].multiply(xi.pow(j)).mod(lambda);
                share = share.add(term).mod(lambda);
            }
            this.privateKeyShares.add(Pair.of(i, share));
        }
        // After generating, save the keys to Redis.
        saveKeyToRedis();
    }

    
    /**
     * 保存密钥到Redis
     */
    public void saveKeyToRedis() {
        Map<String, String> keyData = new HashMap<>();
        keyData.put("n", this.n.toString(16));
        keyData.put("e", this.e.toString(16));
        keyData.put("d", this.d.toString(16));
        keyData.put("numOfServer", String.valueOf(this.numOfServer));
        keyData.put("threshold", String.valueOf(this.threshold));
        
        // 保存私钥份额
        for (Pair<Integer, BigInteger> sharePair : this.privateKeyShares) {
            keyData.put("share." + sharePair.getFirst(), sharePair.getSecond().toString(16));
        }
        
        redisStorage.storeThresholdKeys(keyData);
        System.out.println("✅ 阈值RSA密钥已保存到Redis");
    }
    
    /**
     * 从Redis加载密钥
     */
    public boolean loadKeyFromRedis() {
        try {
            Map<String, String> keyData = redisStorage.retrieveThresholdKeys();
            if (keyData == null || keyData.isEmpty()) {
                System.out.println("▶️ Redis中没有找到阈值密钥，将使用文件或生成新密钥");
                return false;
            }
            
            this.n = new BigInteger(keyData.get("n"), 16);
            this.e = new BigInteger(keyData.get("e"), 16);
            this.d = new BigInteger(keyData.get("d"), 16);
            this.numOfServer = Integer.parseInt(keyData.get("numOfServer"));
            this.threshold = Integer.parseInt(keyData.get("threshold"));
            
            this.privateKeyShares = new ArrayList<>();
            for (int i = 1; i <= this.numOfServer; i++) {
                String hexShare = keyData.get("share." + i);
                if (hexShare == null) {
                    System.out.println("▶️ Redis中密钥数据不完整，将使用文件或生成新密钥");
                    return false;
                }
                this.privateKeyShares.add(Pair.of(i, new BigInteger(hexShare, 16)));
            }
            
            System.out.println("✅ 阈值RSA密钥已从Redis成功加载");
            return true;
        } catch (Exception e) {
            System.err.println("❌ 从Redis加载密钥失败: " + e.getMessage());
            return false;
        }
    }


    @Override
    public Map<String, Object> getKeySet() {
        if (this.privateKeyShares == null || this.n == null) {
            throw new IllegalStateException("Keys have not been generated or loaded yet.");
        }
        // 创建一个新的Map副本，以防止外部代码修改内部状态
        Map<String, Object> keySet = new HashMap<>();
        keySet.put(PRIVATE_KEY_SHARE, this.privateKeyShares);
        keySet.put(PUBLIC_KEY, this.n);
        return keySet;
    }

    @Override
    public PublicKey getPublicKey() {
        if (this.n == null || this.e == null) {
            throw new IllegalStateException("Keys have not been generated or loaded yet.");
        }
        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(this.n, this.e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to create public key object.", ex);
        }
    }

    @Override
    public byte[] sign(String content) {
        try {
            // 4. 从 n 和 d 重建 RSA 私钥。
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);
            PrivateKey rsaPrivateKey = keyFactory.generatePrivate(privateKeySpec);

            // 5. 使用 RSA 私钥签署证书内容。
            // 签名算法改为 "SHA256withRSA"。
            Signature rsaSign = Signature.getInstance("SHA256withRSA");
            rsaSign.initSign(rsaPrivateKey);
            rsaSign.update(content.getBytes(StandardCharsets.UTF_8));
            return rsaSign.sign();
        } catch (NoSuchAlgorithmException e) {
            // 处理算法不支持的情况（如 "RSA" 或 "SHA256withRSA" 不可用）
            throw new RuntimeException("当前Java环境不支持RSA或SHA256withRSA算法", e);
        }  catch (InvalidKeyException e) {
            // 处理无效的私钥
            throw new RuntimeException("无效的RSA私钥", e);
        } catch (SignatureException | InvalidKeySpecException e) {
            // 处理签名过程中的错误（如初始化失败或更新数据失败）
            throw new RuntimeException("签名过程中发生错误", e);
        }
    }

    public static boolean verify(String content, byte[] signature, PublicKey publicKey) {
        try {
            // 1. 初始化用于验证的 Signature 对象。
            //    算法必须与签名时使用的算法 ("SHA256withRSA") 相同。
            Signature rsaVerify = Signature.getInstance("SHA256withRSA");
            rsaVerify.initVerify(publicKey);

            // 2. 提供原始数据给 Signature 对象。
            rsaVerify.update(content.getBytes(StandardCharsets.UTF_8));

            // 3. 验证签名。
            return rsaVerify.verify(signature);

        } catch (NoSuchAlgorithmException ex) {
            // 处理算法不支持的情况
            throw new RuntimeException("当前Java环境不支持RSA或SHA256withRSA算法", ex);
        } catch (InvalidKeyException ex) {
            // 处理无效的公钥
            throw new RuntimeException("无效的RSA公钥", ex);
        } catch (SignatureException ex) {
            // 处理验证过程中的错误（如签名格式不正确）
            throw new RuntimeException("签名验证过程中发生错误", ex);
        }
    }
}