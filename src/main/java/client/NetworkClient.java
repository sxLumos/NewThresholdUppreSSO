package client;

import config.SystemConfig;
import network.ClientNetworkManager;
import network.NetworkMessage;
import org.bouncycastle.math.ec.ECPoint;
import storage.RedisStorage;
import utils.CryptoUtil;
import utils.Lagrange;
import utils.Pair;
import verifier.ThresholdRSAJWTVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.*;

/**
 * 使用网络通信的客户端
 */
public class NetworkClient {
    private String username;
    private String password;
    public static final int numOfServer = SystemConfig.NUM_SERVERS;
    public static final int threshold = SystemConfig.THRESHOLD;
    private static final String USER_ID_KEY = "user_id";
    private static final MessageDigest DIGEST;
    private final ClientNetworkManager networkManager;
    private final RedisStorage redisStorage;
    private PublicKey publicKey;
    
    static {
        try {
            DIGEST = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No such hash algorithm", e);
        }
    }
    
    public static void main(String[] args) {
        try {
            NetworkClient client = new NetworkClient("shenxin", "123456");

            // 初始化系统（这里需要先启动服务器）
            System.out.println("请确保服务器已启动，然后按回车键继续...");
            try {
                System.in.read();
            } catch (IOException e) {
                e.printStackTrace();
            }

            long a = System.currentTimeMillis();
            client.register(numOfServer, threshold);
            long b = System.currentTimeMillis();
            System.out.printf("User Register: %d ms\n", b - a);

            // 模拟多次登录
            for (int i = 0; i < 1; i++) {
                client.login();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            RedisStorage.getInstance().close();
        }
    }
    
    public NetworkClient(String username, String password) {
        this.username = username;
        this.password = password;
        this.networkManager = new ClientNetworkManager();
        this.redisStorage = RedisStorage.getInstance();
    }
    
    public void register(int n, int t) {
        try {
            byte[] input = DIGEST.digest((username + password).getBytes(StandardCharsets.UTF_8));
            Pair<BigInteger, List<Pair<Integer, BigInteger>>> TOPRFShareEnc = generateTOPRFKeyShare(n, t);
            BigInteger masterPrivateKeyEnc = TOPRFShareEnc.getFirst();
            List<Pair<Integer, BigInteger>> privateKeyShareEnc = TOPRFShareEnc.getSecond();
            
            byte[] y = CryptoUtil.calculateExpectedOutput(input, masterPrivateKeyEnc);
            List<byte[]> serverSymmetricKeys = generateSymmetricKeys(y);
            
            Pair<BigInteger, List<Pair<Integer, BigInteger>>> TOPRFShareUserID = generateTOPRFKeyShare(n, t);
            BigInteger masterPrivateKeyUserID = TOPRFShareUserID.getFirst();
            List<Pair<Integer, BigInteger>> privateKeyShareUserID = TOPRFShareUserID.getSecond();
            byte[] UserID = CryptoUtil.calculateExpectedOutput(input, masterPrivateKeyUserID);
            
            List<Pair<byte[], byte[]>> serverStoreRecord = new ArrayList<>();
            for (int i = 1; i <= n; i++) {
                DIGEST.update(UserID);
                DIGEST.update(BigInteger.valueOf(i).toByteArray());
                byte[] key = DIGEST.digest();
                byte[] value = serverSymmetricKeys.get(i - 1);
                serverStoreRecord.add(Pair.of(key, value));
            }
            
//            saveUserIDToRedis(UserID);
            
            // 通过网络发送注册请求
            NetworkMessage response = networkManager.sendUserRegisterRequest(
                privateKeyShareEnc, privateKeyShareUserID, serverStoreRecord);
            
            if (networkManager.isSuccessResponse(response)) {
                System.out.println("✅ 用户注册成功");
            } else {
                System.err.println("❌ 用户注册失败: " + networkManager.getErrorMessage(response));
            }
            
        } catch (Exception e) {
            System.err.println("❌ 注册过程中发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public void login() {
        try {
            long a = System.currentTimeMillis();
            // 通过TOPRF与t个IdP在线计算UserID（不再从Redis读取）
            byte[] userInputForUserId = DIGEST.digest((username + password).getBytes(StandardCharsets.UTF_8));
            ECPoint h1_userId = CryptoUtil.hashToPoint(userInputForUserId);
            BigInteger r_userId = CryptoUtil.randomScalar();
            ECPoint a_userId = h1_userId.multiply(r_userId).normalize();
            String aUserIdHex = CryptoUtil.bytesToHex(a_userId.getEncoded(true));

            Set<Integer> chosenForUserId = new HashSet<>();
            Random randForUserId = new Random();
            while (chosenForUserId.size() < threshold) {
                int sid = randForUserId.nextInt(numOfServer) + 1;
                chosenForUserId.add(sid);
            }
            int[] serverIndicesForUserId = chosenForUserId.stream().mapToInt(Integer::intValue).toArray();
            ECPoint combinedB_userId = CryptoUtil.EC_SPEC.getCurve().getInfinity();
            for (int sid : chosenForUserId) {
                NetworkMessage resp = networkManager.sendUserIdOPRFShareRequestToServerId(sid, aUserIdHex);
                Pair<Integer, String> pair = networkManager.deserializeUserIdOPRFShare(resp);
                if (pair != null) {
                    int i = pair.getFirst();
                    ECPoint bi = CryptoUtil.decodePointFromHex(pair.getSecond());
                    BigInteger lambda_i = Lagrange.getCoefficient(i, serverIndicesForUserId, CryptoUtil.ORDER);
                    combinedB_userId = combinedB_userId.add(bi.multiply(lambda_i));
                }
            }
            combinedB_userId = combinedB_userId.normalize();
            BigInteger r_inv_userId = r_userId.modInverse(CryptoUtil.ORDER);
            ECPoint unblinded_userId = combinedB_userId.multiply(r_inv_userId).normalize();
            byte[] UserID = CryptoUtil.hashPointToBytes(unblinded_userId);
            
            // 1) 从RP获取 ID_RP 与 Cert_RP
            NetworkMessage rpCertResp = networkManager.sendRPCertRequest();
            if (!networkManager.isSuccessResponse(rpCertResp)) {
                System.err.println("❌ 无法从RP获取证书: " + networkManager.getErrorMessage(rpCertResp));
                return;
            }
            String idRpHex = (String) rpCertResp.getData().get("identity");
            String publicKeyBase64 = (String) rpCertResp.getData().get("publicKey");
            String certSigHex = (String) rpCertResp.getData().get("signature");
            String rpHostFromCert = (String) rpCertResp.getData().get("rpHost");
            ECPoint ID_RP = CryptoUtil.decodePointFromHex(idRpHex);

            // 2) 验证RP证书签名（使用系统公钥）
            if (publicKeyBase64 != null && certSigHex != null) {
                try {
                    byte[] pkBytes = Base64.getDecoder().decode(publicKeyBase64);
                    java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(pkBytes);
                    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
                    this.publicKey = kf.generatePublic(spec);

                    // ======================== 开始修正 ========================
                    // 必须使用与RP端完全相同的门限签名验证逻辑

                    // 1. 构造与RP端完全一致的消息并计算哈希
                    String contentHex = CryptoUtil.bytesToHex(ID_RP.getEncoded(true)) + ":" + rpHostFromCert;
                    byte[] contentBytes = contentHex.getBytes(StandardCharsets.UTF_8);
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    BigInteger messageHash = new BigInteger(1, digest.digest(contentBytes));

                    // 2. 解码签名
                    BigInteger finalSig = new BigInteger(certSigHex, 16);

                    // 3. 获取公钥参数
                    java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) this.publicKey;
                    BigInteger n = rsaPublicKey.getModulus();
                    BigInteger e = rsaPublicKey.getPublicExponent();

                    // 4. 计算验证公式的左边: sig^e mod n
                    BigInteger left = finalSig.modPow(e, n);

                    // 5. 计算 t! (delta)
                    BigInteger delta = BigInteger.ONE;
                    for (int i = 2; i <= SystemConfig.THRESHOLD; i++) {
                        delta = delta.multiply(BigInteger.valueOf(i));
                    }

                    // 6. 计算验证公式的右边: H(m)^{t!} mod n
                    BigInteger right = messageHash.modPow(delta, n);

                    // 7. 比较两边是否相等
                    boolean ok = left.equals(right);

                    if (!ok) {
                        System.err.println("❌ RP证书签名校验失败");
                        return;
                    }
                } catch (Exception e) {
                    System.err.println("❌ RP证书校验异常: " + e.getMessage());
                    return;
                }
            }

            // 3) 生成随机数t和伪身份
            BigInteger t = CryptoUtil.randomScalar();
            ECPoint PID_RP = ID_RP.multiply(t).normalize();
            
            BigInteger userIDScalar = CryptoUtil.hashToScalar(UserID);
            ECPoint PID_U = PID_RP.multiply(userIDScalar).normalize();
            
            Map<String, Object> infos = new HashMap<>();
            String pidRpBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(PID_RP.getEncoded(true));
            String pidUBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(PID_U.getEncoded(true));
            infos.put("pid_rp", pidRpBase64);
            infos.put("pid_u", pidUBase64);
            
            // 生成盲化输入（用于加密token份额的TOPRF）
            byte[] userInput = DIGEST.digest((username + password).getBytes(StandardCharsets.UTF_8));
            ECPoint h1x = CryptoUtil.hashToPoint(userInput);
            BigInteger r = CryptoUtil.randomScalar();
            ECPoint blindedPoint_a = h1x.multiply(r).normalize();
            
            long startTimeSec = System.currentTimeMillis() / 1000L;

            // 向随机t个不同的服务器分别请求本地份额
            Set<Integer> chosen = new HashSet<>();
            Random rand = new Random();
            while (chosen.size() < threshold) {
                int sid = rand.nextInt(numOfServer) + 1;
                chosen.add(sid);
            }
//            System.out.println(chosen);
            List<Pair<Integer, Pair<String, String>>> tokenShares = new ArrayList<>();
            for (int sid : chosen) {
                NetworkMessage resp = networkManager.sendTokenShareRequestToServerId(
                        sid,
                        UserID,
                        CryptoUtil.bytesToHex(blindedPoint_a.getEncoded(true)),
                        startTimeSec,
                        infos
                );
                if (networkManager.isSuccessResponse(resp)) {
                    tokenShares.addAll(networkManager.deserializeTokenShares(resp));
                }
            }

            long b = System.currentTimeMillis();
            System.out.printf("Token Request (t servers): %d ms\n", b - a);
            
            if (!tokenShares.isEmpty()) {
                a = System.currentTimeMillis();
                List<Pair<Integer, Pair<String, ECPoint>>> processedShares = new ArrayList<>();
                
                for (Pair<Integer, Pair<String, String>> share : tokenShares) {
                    int serverId = share.getFirst();
                    String encryptedToken = share.getSecond().getFirst();
                    ECPoint ecPoint = CryptoUtil.decodePointFromHex(share.getSecond().getSecond());
                    processedShares.add(Pair.of(serverId, Pair.of(encryptedToken, ecPoint)));
                }
                
                byte[] y = combineTOPRFShare(r, processedShares);
                List<byte[]> keys = generateSymmetricKeys(y);
                String completeToken = ThresholdRSAJWTVerifier.combineJwtShares(keys, processedShares, publicKey, threshold);
                
                b = System.currentTimeMillis();
                System.out.printf("Token Construct: %d ms\n", b - a);

                // 通过RP服务器验证令牌
                a = System.currentTimeMillis();
                NetworkMessage verifyResponse = networkManager.sendTokenVerifyRequest(completeToken);
                
                if (networkManager.isSuccessResponse(verifyResponse)) {
                    // 去盲化
                    String pidUBase64FromJwt = (String) verifyResponse.getData().get("pid_u");
                    byte[] pidUBytes = Base64.getUrlDecoder().decode(pidUBase64FromJwt);
                    ECPoint blindedPidUFromJwt = CryptoUtil.EC_SPEC.getCurve().decodePoint(pidUBytes);
                    
                    BigInteger t_inverse = t.modInverse(CryptoUtil.ORDER);
                    ECPoint final_IDU_IDRP = blindedPidUFromJwt.multiply(t_inverse).normalize();
                    // final_IDU_IDRP 可以用于后续的身份验证逻辑
                    
                    b = System.currentTimeMillis();
                    System.out.printf("Token Verify: %d ms\n", b - a);
                    System.out.println("\n🎉 SUCCESS: 登录成功！");
                    System.out.println("Token验证通过RP服务器完成");
                } else {
                    System.err.println("❌ Token验证失败: " + networkManager.getErrorMessage(verifyResponse));
                }
                
            } else {
                System.err.println("❌ 令牌请求失败: 未获取到足够的份额");
            }
            
        } catch (Exception e) {
            System.err.println("❌ 登录过程中发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 获取RP的公钥（这里简化处理，实际应该从服务器获取）
     */
    private ECPoint getRPPublicKey() {
        // 这里应该从服务器获取RP的公钥，现在简化处理
        return CryptoUtil.GENERATOR.multiply(BigInteger.valueOf(12345)).normalize();
    }
    
    public static byte[] combineTOPRFShare(BigInteger r, List<Pair<Integer, Pair<String, ECPoint>>> shares) {
        BigInteger order = CryptoUtil.ORDER;
        int[] serverIndices = shares.stream().mapToInt(Pair::getFirst).toArray();
        ECPoint combinedResultB = CryptoUtil.EC_SPEC.getCurve().getInfinity();
        
        for (Pair<Integer, Pair<String, ECPoint>> share : shares) {
            int i = share.getFirst();
            ECPoint bi = share.getSecond().getSecond();
            
            BigInteger lambda_i = Lagrange.getCoefficient(i, serverIndices, order);
            ECPoint term = bi.multiply(lambda_i);
            combinedResultB = combinedResultB.add(term);
        }
        combinedResultB = combinedResultB.normalize();
        
        BigInteger r_inv = r.modInverse(order);
        ECPoint unblindedResult = combinedResultB.multiply(r_inv).normalize();
        
        return CryptoUtil.hashPointToBytes(unblindedResult);
    }
    
    public static List<byte[]> generateSymmetricKeys(byte[] input) {
        List<byte[]> serverSymmetricKeys = new ArrayList<>();
        try {
            for (int i = 1; i <= numOfServer; i++) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(input);
                digest.update(BigInteger.valueOf(i).toByteArray());
                byte[] key_i = digest.digest();
                serverSymmetricKeys.add(key_i);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to derive symmetric keys for servers.", e);
        }
        return serverSymmetricKeys;
    }
    
    public static Pair<BigInteger, List<Pair<Integer, BigInteger>>> generateTOPRFKeyShare(int n, int t) {
        BigInteger[] coefficients = new BigInteger[t];
        for (int i = 0; i < t; i++) {
            coefficients[i] = CryptoUtil.randomScalar();
        }
        
        BigInteger masterPrivateKey = coefficients[0];
        List<Pair<Integer, BigInteger>> TOPRFKeyShare = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            BigInteger xi = BigInteger.valueOf(i);
            BigInteger privateKeyShare = BigInteger.ZERO;
            for (int j = 0; j < t; j++) {
                BigInteger term = coefficients[j].multiply(xi.pow(j)).mod(CryptoUtil.ORDER);
                privateKeyShare = privateKeyShare.add(term).mod(CryptoUtil.ORDER);
            }
            TOPRFKeyShare.add(Pair.of(i, privateKeyShare));
        }
        return Pair.of(masterPrivateKey, TOPRFKeyShare);
    }
    
    public void saveUserIDToRedis(byte[] userID) {
        try {
            String userKey = USER_ID_KEY + ":" + username;
            String userIDHex = CryptoUtil.bytesToHex(userID);
            redisStorage.storeClientData(userKey, userIDHex);
            System.out.println("✅ 用户ID已保存到Redis");
        } catch (Exception e) {
            System.err.println("❌ 保存用户ID到Redis失败: " + e.getMessage());
            throw new RuntimeException("Failed to save UserID to Redis.", e);
        }
    }
    
    public byte[] loadUserIDFromRedis() {
        try {
            String userKey = USER_ID_KEY + ":" + username;
            String userIDHex = redisStorage.retrieveClientData(userKey);
            if (userIDHex != null) {
                return CryptoUtil.hexToBytes(userIDHex);
            }
            return null;
        } catch (Exception e) {
            System.err.println("❌ 从Redis加载用户ID失败: " + e.getMessage());
            return null;
        }
    }
}
