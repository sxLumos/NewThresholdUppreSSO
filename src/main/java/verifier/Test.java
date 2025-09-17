package verifier;

import server.idp.ThresholdRSAJWTTokenGenerator;
import server.idp.ThresholdRSAKeyGenerator;
import utils.Pair;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Test {
    // --- 测试参数 ---
    private static final int NUM_OF_SERVERS = 10; // 系统中的服务器总数
    private static final int THRESHOLD = 3;      // 签名的门限值 (t)

    // --- 测试对象 ---
    private ThresholdRSAKeyGenerator keyGenerator;
    private List<ThresholdRSAJWTTokenGenerator> servers;
    private RSAPublicKey publicKey;
    private BigInteger n; // RSA 公共模数

    public static void main(String[] args) throws Exception {
        Test s = new Test();
        s.setUp();
        for(int i = 0;i < 10;i ++ ) {
            s.endToEnd_WithExactThresholdShares_ShouldSucceed();
        }
    }
    void setUp() {
        // 1. 初始化密钥生成器并生成密钥和份额
        keyGenerator = new ThresholdRSAKeyGenerator(NUM_OF_SERVERS, THRESHOLD, true);

        // 获取公钥和私钥份额
        publicKey = (RSAPublicKey) keyGenerator.getPublicKey();
        n = publicKey.getModulus();
        List<Pair<Integer, BigInteger>> privateKeyShares = (List<Pair<Integer, BigInteger>>) keyGenerator.getKeySet().get(ThresholdRSAKeyGenerator.PRIVATE_KEY_SHARE);

        // 2. 根据私钥份额，创建并初始化所有模拟的签名服务器
        servers = new ArrayList<>();
        for (Pair<Integer, BigInteger> share : privateKeyShares) {
            int serverId = share.getFirst();
            BigInteger d_i = share.getSecond();
            servers.add(new ThresholdRSAJWTTokenGenerator(n, d_i, serverId));
        }

        System.out.println("✅ 测试环境初始化完成：已生成密钥并创建 " + NUM_OF_SERVERS + " 个模拟服务器。");
    }
    void endToEnd_WithExactThresholdShares_ShouldSucceed() throws Exception {
        // --- 1. 准备 (Arrange) ---
        // 定义一条所有服务器都要签名的消息
        String message = "This is a test message for threshold signature.";
        byte[] contentBytes = message.getBytes(StandardCharsets.UTF_8);

        // 从所有服务器中随机选取 't' 个参与签名
        List<ThresholdRSAJWTTokenGenerator> participatingServers = new ArrayList<>(servers);
        Collections.shuffle(participatingServers);
        participatingServers = participatingServers.subList(0, THRESHOLD);
        System.out.println("ℹ️ 参与签名的服务器ID: " + participatingServers.stream().map(s -> s.getSid()).toList());

        // --- 2. 执行 (Act) ---
        // 2.1. 各参与服务器生成自己的签名份额
        List<PartialSignature> partialSignatures = new ArrayList<>();
        for (ThresholdRSAJWTTokenGenerator server : participatingServers) {
            BigInteger shareValue = server.generateSignatureShare(contentBytes);
            partialSignatures.add(new PartialSignature(server.getSid(), shareValue));
        }

        // 2.2. 验证者聚合签名份额
        // **注意：这里调用你修改后的、标准的 combineSignatures 方法**
        BigInteger finalSignature = ThresholdRSAJWTVerifier.combineSignatures(partialSignatures, n);

        // 2.3. 验证者对最终签名进行校验
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        BigInteger messageHash = new BigInteger(1, digest.digest(contentBytes));
        BigInteger e = publicKey.getPublicExponent();

        // **注意：这里调用你修改后的、标准的 verifyThresholdSignature 方法**
        boolean isVerified = ThresholdRSAJWTVerifier.verifyThresholdSignature(messageHash, finalSignature, n, e);
        System.out.println(isVerified);
    }
}
