package client;

import config.SystemConfig;
import network.ClientNetworkManager;
import network.NetworkMessage;
import org.bouncycastle.math.ec.ECPoint;
import utils.CryptoUtil;
import utils.Lagrange;
import utils.Pair;
import utils.SimpleBenchmark;
import verifier.ThresholdRSAJWTVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;

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
    private List<Pair<Integer, Pair<String, String>>> tokenShare;
    private static final int benchmarkRuns = 10;
    private BigInteger r;
//    private final RedisStorage redisStorage;
    private static final ExecutorService executor;
    private PublicKey publicKey;
    
    static {
        try {
            DIGEST = MessageDigest.getInstance("SHA-256");
            executor = Executors.newFixedThreadPool(SystemConfig.CONCURRENT_REQUEST_THREADS);
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
            // 1. 在所有操作开始前，重置一次计数器
            client.networkManager.resetCounters();

            Runnable userRegisterTask = () -> client.register(numOfServer, threshold);
            Runnable userTokenRequestTask = client::login;
            Runnable userTokenVerify = client::verify;
            double a = SimpleBenchmark.getAverageTime(benchmarkRuns, userRegisterTask);
            double b = SimpleBenchmark.getAverageTime(benchmarkRuns, userTokenRequestTask);
            double c = SimpleBenchmark.getAverageTime(benchmarkRuns, userTokenVerify);
            System.out.printf("User注册耗时: %.0f ms\n", a);
            System.out.printf("User请求Token耗时: %.0f ms\n", b);
            System.out.printf("验证Token耗时: %.0f ms\n", c);
            // 2. 在所有操作结束后，获取并打印总的通信代价
            long totalSent = client.networkManager.getTotalBytesSent();
            long totalReceived = client.networkManager.getTotalBytesReceived();
            long totalComm = totalSent + totalReceived;

            System.out.printf(
                    "\n============================================\n" +
                            "      总通信代价统计 (所有操作合计)\n" +
                            "--------------------------------------------\n" +
                            "  - 总发送量: %.2f KB\n" +
                            "  - 总接收量: %.2f KB\n" +
                            "  - 总通信量: %.2f KB\n" +
                            "============================================\n",
                    (double) totalSent / (1024.0 * benchmarkRuns),
                    (double) totalReceived / (1024.0 * benchmarkRuns),
                    (double) totalComm / (1024.0 * benchmarkRuns)
            );
            executor.shutdown();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public NetworkClient(String username, String password) {
        this.username = username;
        this.password = password;
        this.networkManager = new ClientNetworkManager();
//        this.redisStorage = RedisStorage.getInstance();
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

            // 1. 并发发送所有注册请求，并将每个请求的结果（成功/失败）转换为一个布尔值
            List<CompletableFuture<Boolean>> futures = IntStream.rangeClosed(1, numOfServer)
                    .mapToObj(sid -> CompletableFuture.supplyAsync(() ->
                                    // 在后台线程池中执行网络请求
                                    networkManager.sendUserRegisterRequest(
                                            sid,
                                            privateKeyShareEnc.get(sid - 1).getSecond(),
                                            privateKeyShareUserID.get(sid - 1).getSecond(),
                                            serverStoreRecord.get(sid - 1)
                                    ), executor)
                            .handle((response, ex) -> {
                                // .handle() 会处理正常结果(response)或异常(ex)
                                if (ex != null || !networkManager.isSuccessResponse(response)) {
                                    // 如果有异常，或者响应内容表示失败
                                    ex.printStackTrace();
                                    String errorMessage = (ex != null)
                                            ? ex.getCause().getMessage()
                                            : networkManager.getErrorMessage(response);
                                    System.err.println("❌ 用户注册失败(sid=" + sid + "): " + errorMessage);
                                    return false; // 代表此请求失败
                                }
                                return true; // 代表此请求成功
                            }))
                    .toList();

            // 2. 等待所有请求完成，然后统计失败的个数
            long failedCount = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .thenApply(v -> futures.stream()
                            .map(CompletableFuture::join) // 获取每个任务的布尔结果
                            .filter(isSuccess -> !isSuccess) // 筛选出所有失败的结果(false)
                            .count() // 计算失败的总数
                    ).join(); // 阻塞等待最终的计数值

            // 3. 根据失败计数，打印最终的总结信息
            if (failedCount == 0) {
                System.out.println("✅ 所有 " + numOfServer + " 个用户注册请求均已成功。");
            } else {
                System.err.println("❌ " + failedCount + " 个用户注册请求失败，请检查上面的错误日志。");
            }
            
        } catch (Exception e) {
            System.err.println("❌ 注册过程中发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public void login() {
        try {
//            long a = System.currentTimeMillis();
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
            this.r = CryptoUtil.randomScalar();
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
            List<CompletableFuture<NetworkMessage>> futures = chosen.stream()
                    .map(sid -> CompletableFuture.supplyAsync(() ->
                                    // 将网络请求作为任务提交到线程池
                                    networkManager.sendTokenShareRequestToServerId(
                                            sid,
                                            UserID,
                                            CryptoUtil.bytesToHex(blindedPoint_a.getEncoded(true)),
                                            startTimeSec,
                                            infos
                                    ), executor) // 使用您的线程池
                            .exceptionally(ex -> {
                                // 如果某个请求出现异常（如超时），打印错误并返回null
                                System.err.println("获取服务器 " + sid + " 的Token份额失败: " + ex.getMessage());
                                return null; // 返回null，以便后续可以过滤掉失败的请求
                            }))
                    .toList();

            // 2. 等待所有请求完成，然后统一处理结果
            List<Pair<Integer, Pair<String, String>>> tokenShares = futures.stream()
                    .map(CompletableFuture::join) // 等待每个异步任务完成并获取结果
                    .filter(Objects::nonNull) // 过滤掉因异常而返回null的任务
                    .filter(networkManager::isSuccessResponse) // 过滤出业务上成功的响应
                    .flatMap(resp -> networkManager.deserializeTokenShares(resp).stream()) // 将每个成功响应中的份额列表(List)展开成一个流(Stream)
                    .toList(); // 将所有份额收集到一个最终的列表中


//            long b = System.currentTimeMillis();
//            System.out.printf("Token Request (t servers): %d ms\n", b - a);
            
            if (!tokenShares.isEmpty()) {
                tokenShare = tokenShares;
            } else {
                System.err.println("❌ 令牌请求失败: 未获取到足够的份额");
            }
        } catch (Exception e) {
            System.err.println("❌ 令牌请求过程中发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    public void verify() {
        List<Pair<Integer, Pair<String, ECPoint>>> processedShares = new ArrayList<>();

        for (Pair<Integer, Pair<String, String>> share : tokenShare) {
            int serverId = share.getFirst();
            String encryptedToken = share.getSecond().getFirst();
            ECPoint ecPoint = CryptoUtil.decodePointFromHex(share.getSecond().getSecond());
            processedShares.add(Pair.of(serverId, Pair.of(encryptedToken, ecPoint)));
        }

        byte[] y = combineTOPRFShare(r, processedShares);
        List<byte[]> keys = generateSymmetricKeys(y);
        String completeToken = ThresholdRSAJWTVerifier.combineJwtShares(keys, processedShares, publicKey, threshold);

        // 通过RP服务器验证令牌
        NetworkMessage verifyResponse = networkManager.sendTokenVerifyRequest(completeToken);

        if (networkManager.isSuccessResponse(verifyResponse)) {
            // 去盲化
//                    String pidUBase64FromJwt = (String) verifyResponse.getData().get("pid_u");
//                    byte[] pidUBytes = Base64.getUrlDecoder().decode(pidUBase64FromJwt);
//                    ECPoint blindedPidUFromJwt = CryptoUtil.EC_SPEC.getCurve().decodePoint(pidUBytes);
//
//                    BigInteger t_inverse = t.modInverse(CryptoUtil.ORDER);
//                    ECPoint final_IDU_IDRP = blindedPidUFromJwt.multiply(t_inverse).normalize();
            // final_IDU_IDRP 可以用于后续的身份验证逻辑

            System.out.println("\n🎉 SUCCESS: 登录成功！");
            System.out.println("Token验证通过RP服务器完成");
        } else {
            System.err.println("❌ Token验证失败: " + networkManager.getErrorMessage(verifyResponse));
        }
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
    
//    public void saveUserIDToRedis(byte[] userID) {
//        try {
//            String userKey = USER_ID_KEY + ":" + username;
//            String userIDHex = CryptoUtil.bytesToHex(userID);
//            redisStorage.storeClientData(userKey, userIDHex);
//            System.out.println("✅ 用户ID已保存到Redis");
//        } catch (Exception e) {
//            System.err.println("❌ 保存用户ID到Redis失败: " + e.getMessage());
//            throw new RuntimeException("Failed to save UserID to Redis.", e);
//        }
//    }
    
//    public byte[] loadUserIDFromRedis() {
//        try {
//            String userKey = USER_ID_KEY + ":" + username;
//            String userIDHex = redisStorage.retrieveClientData(userKey);
//            if (userIDHex != null) {
//                return CryptoUtil.hexToBytes(userIDHex);
//            }
//            return null;
//        } catch (Exception e) {
//            System.err.println("❌ 从Redis加载用户ID失败: " + e.getMessage());
//            return null;
//        }
//    }
}
