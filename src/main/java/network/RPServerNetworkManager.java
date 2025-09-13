package network;

import com.auth0.jwt.interfaces.DecodedJWT;
import config.SystemConfig;
import org.bouncycastle.math.ec.ECPoint;
import server.rp.RelyingParty;
import utils.CryptoUtil;
import verifier.ThresholdRSAJWTVerifier;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.security.PublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * RP服务器网络管理器，负责处理客户端请求和Token验证
 */
public class RPServerNetworkManager {
    private static final int RP_SERVER_PORT = SystemConfig.RP_SERVER_PORT; // RP使用配置端口
    private static final int MAX_THREADS = SystemConfig.RP_SERVER_THREADS;
    private static final String RP_HOST = SystemConfig.RP_HOST; // not used directly now
    private PublicKey publicKey;
    private final RelyingParty relyingParty;
    private final ExecutorService threadPool;
    private volatile boolean running;
    
    public RPServerNetworkManager() {
        this.relyingParty = new RelyingParty();
        this.threadPool = Executors.newFixedThreadPool(MAX_THREADS);
        this.running = false;
        
        // 通过网络向至少t个IdP服务器发起RP注册，获取 (rpHost,idRp) 与签名份额，并合成验证
        try {
            List<Integer> chosen = new ArrayList<>();
            java.util.Random rand = new java.util.Random();
            while (chosen.size() < SystemConfig.THRESHOLD) {
                int sid = rand.nextInt(SystemConfig.NUM_SERVERS) + 1;
                if (!chosen.contains(sid)) chosen.add(sid);
            }
            List<verifier.PartialSignature> partials = new ArrayList<>();
            String idRpHex = null;
            String publicKeyBase64 = null;
            for (int sid : chosen) {
                NetworkMessage resp = requestRPRegisterFromServerId(sid, RP_HOST);
                if (resp != null && resp.getData() != null && Boolean.TRUE.equals(resp.getData().get("success"))) {
                    if (idRpHex == null) idRpHex = (String) resp.getData().get("idRp");
                    if (publicKeyBase64 == null) publicKeyBase64 = (String) resp.getData().get("publicKey");
                    int serverId = Integer.parseInt((String) resp.getData().get("serverId"));
                    java.math.BigInteger share = new java.math.BigInteger((String) resp.getData().get("sigShare"), 16);
                    partials.add(new verifier.PartialSignature(serverId, share));
                }
            }
            if (idRpHex == null || publicKeyBase64 == null || partials.size() < SystemConfig.THRESHOLD) {
                System.err.println("❌ 无法从足够的IdP获取RP注册份额");
            } else {
                // 合成签名并验证
                ECPoint idRp = CryptoUtil.decodePointFromHex(idRpHex);
                byte[] pkBytes = Base64.getDecoder().decode(publicKeyBase64);
                java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(pkBytes);
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
                this.publicKey = kf.generatePublic(spec);
                // 计算消息哈希: H( idRp || rpHost )
                String contentHex = CryptoUtil.bytesToHex(idRp.getEncoded(true)) + ":" + RP_HOST;
                byte[] contentBytes = contentHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                java.math.BigInteger messageHash = new java.math.BigInteger(1, digest.digest(contentBytes));
                java.math.BigInteger n = ((java.security.interfaces.RSAPublicKey) publicKey).getModulus();

                java.math.BigInteger finalSig = verifier.ThresholdRSAJWTVerifier.combineSignatures(partials, n, SystemConfig.THRESHOLD);

                // 验证 threshold RSA: sig^e == H(m)^{t!}
                java.math.BigInteger e = ((java.security.interfaces.RSAPublicKey) publicKey).getPublicExponent();
                java.math.BigInteger left = finalSig.modPow(e, n);
                // expected = H(m)^{t!} mod n
                java.math.BigInteger delta = java.math.BigInteger.ONE;
                for (int i = 2; i <= SystemConfig.THRESHOLD; i++) delta = delta.multiply(java.math.BigInteger.valueOf(i));
                java.math.BigInteger right = messageHash.modPow(delta, n);
                boolean ok = left.equals(right);

                if (!ok) {
                    System.err.println("❌ RP注册签名验证失败");
                } else {
                    // 记录 rpHost 并保存证书
                    this.relyingParty.setRpHost(RP_HOST);
                    this.relyingParty.setIdentityAndCert(idRp, finalSig.toByteArray());
                    this.cachedPublicKeyBase64 = publicKeyBase64;
                    storage.RedisStorage.getInstance().storeRPState("default_rp", idRpHex, CryptoUtil.bytesToHex(finalSig.toByteArray()), publicKeyBase64, RP_HOST);
                }
            }
        } catch (Exception e) {
            System.err.println("❌ RP注册流程失败: " + e.getMessage());
        }
    }

    private String cachedPublicKeyBase64;

    private NetworkMessage requestRPRegisterFromServerId(int serverId, String rpHost) {
        try {
            String requestId = "req_rp_reg_" + System.currentTimeMillis();
            java.util.Map<String, Object> data = new java.util.HashMap<>();
            data.put("rpHost", rpHost);
            NetworkMessage req = new NetworkMessage(MessageTypes.RP_REGISTER, requestId, data);
            int port = SystemConfig.BASE_PORT + (serverId - 1);
            try (Socket socket = new Socket()) {
                socket.connect(new java.net.InetSocketAddress(SystemConfig.SERVER_HOST, port), SystemConfig.CONNECTION_TIMEOUT_MS);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(req);
                out.flush();
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                return (NetworkMessage) in.readObject();
            }
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * 启动RP服务器
     */
    public void start() {
        running = true;
        System.out.println("🚀 RP服务器启动，监听端口: " + RP_SERVER_PORT);
        
        try (ServerSocket serverSocket = new ServerSocket(RP_SERVER_PORT)) {
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("📡 新客户端连接到RP: " + clientSocket.getRemoteSocketAddress());
                    
                    // 为每个客户端连接创建新的处理线程
                    threadPool.submit(new RPClientHandler(clientSocket));
                } catch (IOException e) {
                    if (running) {
                        System.err.println("❌ 接受客户端连接失败: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("❌ RP服务器启动失败: " + e.getMessage());
        }
    }
    
    /**
     * 停止RP服务器
     */
    public void stop() {
        running = false;
        threadPool.shutdown();
        System.out.println("🛑 RP服务器已停止");
    }
    
    /**
     * RP客户端请求处理器
     */
    private class RPClientHandler implements Runnable {
        private final Socket clientSocket;
        
        public RPClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }
        
        @Override
        public void run() {
            try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
                 ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {
                
                // 读取客户端请求
                NetworkMessage request = (NetworkMessage) in.readObject();
                System.out.println("📨 RP收到请求: " + request.getMessageType());
                
                // 处理请求并生成响应
                NetworkMessage response = processRPRequest(request);
                
                // 发送响应
                out.writeObject(response);
                out.flush();
                
                System.out.println("📤 RP响应已发送: " + response.getMessageType());
                
            } catch (Exception e) {
                System.err.println("❌ 处理RP客户端请求失败: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    System.err.println("❌ 关闭RP客户端连接失败: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * 处理不同类型的RP请求
     */
    private NetworkMessage processRPRequest(NetworkMessage request) {
        try {
            switch (request.getMessageType()) {
                case MessageTypes.RP_LOGIN_REQUEST:
                    return handleRPLoginRequest(request);
                case MessageTypes.TOKEN_VERIFY_REQUEST:
                    return handleTokenVerifyRequest(request);
                case MessageTypes.RP_CERT_REQUEST:
                    return handleRPCertRequest(request);
                default:
                    return createErrorResponse(request.getRequestId(), "未知的RP请求类型: " + request.getMessageType());
            }
        } catch (Exception e) {
            System.err.println("❌ 处理RP请求时发生错误: " + e.getMessage());
            e.printStackTrace();
            return createErrorResponse(request.getRequestId(), "RP服务器内部错误: " + e.getMessage());
        }
    }
    
    /**
     * 处理RP登录请求
     */
    private NetworkMessage handleRPLoginRequest(NetworkMessage request) {
        try {
            Map<String, Object> data = request.getData();
            
            // 获取用户凭据
            String username = (String) data.get("username");
            String password = (String) data.get("password");
            
            if (username == null || password == null) {
                return createErrorResponse(request.getRequestId(), "用户名或密码不能为空");
            }
            
            // 这里可以添加用户认证逻辑
            // 现在简化处理，直接返回成功
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("message", "RP登录成功");
            responseData.put("username", username);
            
            return new NetworkMessage(MessageTypes.RP_LOGIN_RESPONSE, request.getRequestId(), responseData);
            
        } catch (Exception e) {
            System.err.println("❌ RP登录请求处理失败: " + e.getMessage());
            return createErrorResponse(request.getRequestId(), "RP登录失败: " + e.getMessage());
        }
    }
    
    /**
     * 处理Token验证请求
     */
    private NetworkMessage handleTokenVerifyRequest(NetworkMessage request) {
        try {
            Map<String, Object> data = request.getData();
            
            // 获取JWT Token
            String jwtToken = (String) data.get("jwtToken");
            if (jwtToken == null) {
                return createErrorResponse(request.getRequestId(), "JWT Token不能为空");
            }
            
            // 验证Token：使用RP注册阶段获得并缓存的系统公钥
            if (this.publicKey == null) {
                return createErrorResponse(request.getRequestId(), "RP未缓存系统公钥，无法验证Token");
            }
            DecodedJWT verifiedJwt = ThresholdRSAJWTVerifier.verify(jwtToken, publicKey, SystemConfig.THRESHOLD);
            
            // 提取Token中的信息
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("message", "Token验证成功");
            responseData.put("issuer", verifiedJwt.getIssuer());
            responseData.put("subject", verifiedJwt.getSubject());
            responseData.put("issuedAt", verifiedJwt.getIssuedAt());
            responseData.put("expiresAt", verifiedJwt.getExpiresAt());
            
            // 提取自定义声明
            if (verifiedJwt.getClaim("pid_rp") != null) {
                responseData.put("pid_rp", verifiedJwt.getClaim("pid_rp").asString());
            }
            if (verifiedJwt.getClaim("pid_u") != null) {
                responseData.put("pid_u", verifiedJwt.getClaim("pid_u").asString());
            }
            
            return new NetworkMessage(MessageTypes.TOKEN_VERIFY_RESPONSE, request.getRequestId(), responseData);
            
        } catch (Exception e) {
            System.err.println("❌ Token验证失败: " + e.getMessage());
            return createErrorResponse(request.getRequestId(), "Token验证失败: " + e.getMessage());
        }
    }
    
    /**
     * 处理RP证书请求
     */
    private NetworkMessage handleRPCertRequest(NetworkMessage request) {
        try {
            // 获取RP证书并附带系统公钥
            server.idp.Certificate cert = relyingParty.getCertificate();
            
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("identity", CryptoUtil.bytesToHex(cert.getID_RP().getEncoded(true)));
            responseData.put("signature", CryptoUtil.bytesToHex(cert.getSignature()));
            if (cert.getRpHost() != null) {
                responseData.put("rpHost", cert.getRpHost());
            }
            if (this.cachedPublicKeyBase64 != null) {
                responseData.put("publicKey", this.cachedPublicKeyBase64);
            }
            
            return new NetworkMessage(MessageTypes.RP_CERT_RESPONSE, request.getRequestId(), responseData);
            
        } catch (Exception e) {
            System.err.println("❌ 获取RP证书失败: " + e.getMessage());
            return createErrorResponse(request.getRequestId(), "获取RP证书失败: " + e.getMessage());
        }
    }
    
    /**
     * 创建错误响应
     */
    private NetworkMessage createErrorResponse(String requestId, String errorMessage) {
        Map<String, Object> errorData = new HashMap<>();
        errorData.put("success", false);
        errorData.put("error", errorMessage);
        return new NetworkMessage(MessageTypes.ERROR_RESPONSE, requestId, errorData);
    }
}
