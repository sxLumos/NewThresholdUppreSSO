package network;

import config.SystemConfig;
import org.bouncycastle.math.ec.ECPoint;
import server.idp.IdentityProviderGroup;
import utils.CryptoUtil;
import utils.Pair;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 服务器端网络管理器，负责处理客户端请求
 */
public class ServerNetworkManager {
    private static final int BASE_PORT = SystemConfig.BASE_PORT;
    private static final int MAX_THREADS = SystemConfig.SERVER_THREADS;
    
    private final IdentityProviderGroup idpGroup;
    private final ExecutorService threadPool;
    private final int serverId;
    private final int serverPort;
    private volatile boolean running;
    
    public ServerNetworkManager(IdentityProviderGroup idpGroup, int serverId) {
        this.idpGroup = idpGroup;
        this.serverId = serverId;
        this.serverPort = BASE_PORT + serverId;
        this.threadPool = Executors.newFixedThreadPool(MAX_THREADS);
        this.running = false;
    }
    
    /**
     * 启动服务器
     */
    public void start() {
        running = true;
        System.out.println("🚀 服务器 " + serverId + " 网络管理器启动，监听端口: " + serverPort);
        
        try (ServerSocket serverSocket = new ServerSocket(serverPort)) {
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("📡 新客户端连接: " + clientSocket.getRemoteSocketAddress());
                    
                    // 为每个客户端连接创建新的处理线程
                    threadPool.submit(new ClientHandler(clientSocket));
                } catch (IOException e) {
                    if (running) {
                        System.err.println("❌ 接受客户端连接失败: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("❌ 服务器启动失败: " + e.getMessage());
        }
    }
    
    /**
     * 停止服务器
     */
    public void stop() {
        running = false;
        threadPool.shutdown();
        System.out.println("🛑 服务器网络管理器已停止");
    }
    
    /**
     * 客户端请求处理器
     */
    private class ClientHandler implements Runnable {
        private final Socket clientSocket;
        
        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }
        
        @Override
        public void run() {
            try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
                 ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {
                
                // 读取客户端请求
                NetworkMessage request = (NetworkMessage) in.readObject();
                System.out.println("📨 收到请求: " + request.getMessageType());
                
                // 处理请求并生成响应
                NetworkMessage response = processRequest(request);
                
                // 发送响应
                out.writeObject(response);
                out.flush();
                
                System.out.println("📤 响应已发送: " + response.getMessageType());
                
            } catch (Exception e) {
                System.err.println("❌ 处理客户端请求失败: " + e.getMessage());
                e.printStackTrace();
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    System.err.println("❌ 关闭客户端连接失败: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * 处理不同类型的请求
     */
    private NetworkMessage processRequest(NetworkMessage request) {
        try {
            switch (request.getMessageType()) {
                case MessageTypes.USER_REGISTER:
                    return handleUserRegister(request);
                case MessageTypes.TOKEN_REQUEST:
                    return handleTokenRequestLocalShare(request);
                case MessageTypes.RP_REGISTER:
                    return handleRPRegister(request);
                case MessageTypes.USERID_OPRF_REQUEST:
                    return handleUserIdOPRFRequest(request);
                default:
                    return createErrorResponse(request.getRequestId(), "未知的请求类型: " + request.getMessageType());
            }
        } catch (Exception e) {
            System.err.println("❌ 处理请求时发生错误: " + e.getMessage());
            e.printStackTrace();
            return createErrorResponse(request.getRequestId(), "服务器内部错误: " + e.getMessage());
        }
    }
    
    /**
     * 处理用户注册请求
     */
    @SuppressWarnings("unchecked")
    private NetworkMessage handleUserRegister(NetworkMessage request) {
        try {
            Map<String, Object> data = request.getData();
            
            // 反序列化数据
            List<Pair<Integer, BigInteger>> keyShareEnc = deserializeKeyShares(
                (List<Map<String, Object>>) data.get("keyShareEnc"));
            List<Pair<Integer, BigInteger>> keyShareUserID = deserializeKeyShares(
                (List<Map<String, Object>>) data.get("keyShareUserID"));
            List<Pair<byte[], byte[]>> serverStoreRecord = deserializeServerStoreRecord(
                (List<Map<String, Object>>) data.get("serverStoreRecord"));
            
            // 执行用户注册
            idpGroup.performUserRegister(keyShareEnc, keyShareUserID, serverStoreRecord);
            
            // 创建成功响应
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("message", "用户注册成功");
            
            return new NetworkMessage(MessageTypes.REGISTER_RESPONSE, request.getRequestId(), responseData);
            
        } catch (Exception e) {
            System.err.println("❌ 用户注册失败: " + e.getMessage());
            return createErrorResponse(request.getRequestId(), "用户注册失败: " + e.getMessage());
        }
    }
    
    /**
     * 处理令牌请求
     */
    @SuppressWarnings("unchecked")
    private NetworkMessage handleTokenRequestLocalShare(NetworkMessage request) {
        try {
            Map<String, Object> data = request.getData();
            
            // 反序列化数据
            byte[] userID = CryptoUtil.hexToBytes((String) data.get("userID"));
            String blindedPointHex = (String) data.get("blindedPoint");
            long startTimeSec = ((Number) data.get("startTimeSec")).longValue();
            Map<String, Object> info = (Map<String, Object>) data.get("info");
            
            // 解析盲化点
            ECPoint blindedPoint = CryptoUtil.decodePointFromHex(blindedPointHex);
            
            // 仅生成本地服务器份额
            Pair<Integer, Pair<String, ECPoint>> localShare = idpGroup.generateTokenShareFor(this.serverId + 1, userID, blindedPoint, startTimeSec, info);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", localShare != null);
            if (localShare != null) {
                List<Map<String, Object>> list = new ArrayList<>();
                Map<String, Object> shareData = new HashMap<>();
                shareData.put("serverId", String.valueOf(localShare.getFirst()));
                shareData.put("encryptedToken", localShare.getSecond().getFirst());
                shareData.put("ecPoint", CryptoUtil.bytesToHex(localShare.getSecond().getSecond().getEncoded(true)));
                list.add(shareData);
                responseData.put("tokenShares", list);
            } else {
                responseData.put("error", "Local share unavailable");
            }
            
            return new NetworkMessage(MessageTypes.TOKEN_RESPONSE, request.getRequestId(), responseData);
            
        } catch (Exception e) {
            System.err.println("❌ 令牌请求处理失败: " + e.getMessage());
            return createErrorResponse(request.getRequestId(), "令牌请求失败: " + e.getMessage());
        }
    }
    
    /**
     * 处理RP注册请求
     */
    private NetworkMessage handleRPRegister(NetworkMessage request) {
        try {
            Map<String, Object> data = request.getData();
            String rpHost = (String) data.get("rpHost");
            if (rpHost == null || rpHost.isEmpty()) {
                return createErrorResponse(request.getRequestId(), "rpHost 不能为空");
            }

            // 计算 idRp = H_to_curve(rpHost)
            ECPoint idRp = CryptoUtil.hashToCurve(rpHost.getBytes());
            String contentHex = CryptoUtil.bytesToHex(idRp.getEncoded(true)) + ":" + rpHost;
            byte[] contentBytes = contentHex.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            // 本地服务器生成签名份额
            int sid = this.serverId + 1;
            server.idp.IdentityProvider idp = idpGroup.getIdp(sid);
            BigInteger sigShare = idp.generateSignatureShare(contentBytes);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("serverId", String.valueOf(sid));
            responseData.put("rpHost", rpHost);
            responseData.put("idRp", CryptoUtil.bytesToHex(idRp.getEncoded(true)));
            responseData.put("sigShare", sigShare.toString(16));
            try {
                byte[] pkEncoded = idpGroup.getPublicKey().getEncoded();
                String pkBase64 = Base64.getEncoder().encodeToString(pkEncoded);
                responseData.put("publicKey", pkBase64);
            } catch (Exception ignore) {}

            return new NetworkMessage(MessageTypes.RP_REGISTER_RESPONSE, request.getRequestId(), responseData);
            
        } catch (Exception e) {
            System.err.println("❌ RP注册失败: " + e.getMessage());
            return createErrorResponse(request.getRequestId(), "RP注册失败: " + e.getMessage());
        }
    }

    /**
     * 处理用户ID的TOPRF份额请求：返回 b_i = a^{k_i_userId}
     */
    private NetworkMessage handleUserIdOPRFRequest(NetworkMessage request) {
        try {
            Map<String, Object> data = request.getData();
            String blindedPointHex = (String) data.get("blindedPoint");
            if (blindedPointHex == null) return createErrorResponse(request.getRequestId(), "缺少盲化点");
            ECPoint blindedPoint = CryptoUtil.decodePointFromHex(blindedPointHex);
            int sid = this.serverId + 1;
            server.idp.IdentityProvider idp = idpGroup.getIdp(sid);
            ECPoint bi = idp.evaluateKeyUserID(blindedPoint);

            Map<String, Object> resp = new HashMap<>();
            resp.put("success", true);
            resp.put("serverId", String.valueOf(sid));
            resp.put("ecPoint", CryptoUtil.bytesToHex(bi.getEncoded(true)));
            return new NetworkMessage(MessageTypes.USERID_OPRF_RESPONSE, request.getRequestId(), resp);
        } catch (Exception e) {
            return createErrorResponse(request.getRequestId(), "UserID OPRF失败: " + e.getMessage());
        }
    }
    
    /**
     * 反序列化密钥份额
     */
    private List<Pair<Integer, BigInteger>> deserializeKeyShares(List<Map<String, Object>> sharesData) {
        List<Pair<Integer, BigInteger>> result = new ArrayList<>();
        for (Map<String, Object> shareData : sharesData) {
            int serverId = Integer.parseInt((String) shareData.get("serverId"));
            BigInteger keyValue = new BigInteger((String) shareData.get("keyValue"), 16);
            result.add(Pair.of(serverId, keyValue));
        }
        return result;
    }
    
    /**
     * 反序列化服务器存储记录
     */
    private List<Pair<byte[], byte[]>> deserializeServerStoreRecord(List<Map<String, Object>> recordsData) {
        List<Pair<byte[], byte[]>> result = new ArrayList<>();
        for (Map<String, Object> recordData : recordsData) {
            byte[] lookupKey = CryptoUtil.hexToBytes((String) recordData.get("lookupKey"));
            byte[] symmetricKey = CryptoUtil.hexToBytes((String) recordData.get("symmetricKey"));
            result.add(Pair.of(lookupKey, symmetricKey));
        }
        return result;
    }
    
    /**
     * 序列化令牌份额
     */
    private List<Map<String, Object>> serializeTokenShares(List<Pair<Integer, Pair<String, ECPoint>>> tokenShares) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Pair<Integer, Pair<String, ECPoint>> share : tokenShares) {
            Map<String, Object> shareData = new HashMap<>();
            shareData.put("serverId", String.valueOf(share.getFirst()));
            shareData.put("encryptedToken", share.getSecond().getFirst());
            shareData.put("ecPoint", CryptoUtil.bytesToHex(share.getSecond().getSecond().getEncoded(true)));
            result.add(shareData);
        }
        return result;
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
