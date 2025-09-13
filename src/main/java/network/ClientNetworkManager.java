package network;

import config.SystemConfig;
import utils.CryptoUtil;
import utils.Pair;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.util.*;

/**
 * 客户端网络管理器，负责与服务器进行网络通信
 */
public class ClientNetworkManager {
    private static final String SERVER_HOST = SystemConfig.SERVER_HOST;
    private static final int BASE_PORT = SystemConfig.BASE_PORT;
    private static final int RP_SERVER_PORT = SystemConfig.RP_SERVER_PORT; // RP服务器端口
    private static final int CONNECTION_TIMEOUT = SystemConfig.CONNECTION_TIMEOUT_MS; // 5秒超时
    private static final int NUM_SERVERS = SystemConfig.NUM_SERVERS;
    
    private final Random random;
    
    public ClientNetworkManager() {
        this.random = new Random();
    }
    
    /**
     * 发送用户注册请求
     */
    public NetworkMessage sendUserRegisterRequest(List<Pair<Integer, BigInteger>> keyShareEnc, 
                                                List<Pair<Integer, BigInteger>> keyShareUserID,
                                                List<Pair<byte[], byte[]>> serverStoreRecord) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("keyShareEnc", serializeKeyShares(keyShareEnc));
            data.put("keyShareUserID", serializeKeyShares(keyShareUserID));
            data.put("serverStoreRecord", serializeServerStoreRecord(serverStoreRecord));
            
            return sendRequest(MessageTypes.USER_REGISTER, data);
        } catch (Exception e) {
            System.err.println("❌ 发送用户注册请求失败: " + e.getMessage());
            return createErrorResponse("用户注册请求失败: " + e.getMessage());
        }
    }
    
    /**
     * 发送令牌请求
     */
    public NetworkMessage sendTokenRequest(byte[] userID, String blindedPointHex, 
                                         long startTimeSec, Map<String, Object> info) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("userID", CryptoUtil.bytesToHex(userID));
            data.put("blindedPoint", blindedPointHex);
            data.put("startTimeSec", startTimeSec);
            data.put("info", info);
            
            return sendRequest(MessageTypes.TOKEN_REQUEST, data);
        } catch (Exception e) {
            System.err.println("❌ 发送令牌请求失败: " + e.getMessage());
            return createErrorResponse("令牌请求失败: " + e.getMessage());
        }
    }
    
    /**
     * 发送RP注册请求
     */
    public NetworkMessage sendRPRegisterRequest() {
        try {
            Map<String, Object> data = new HashMap<>();
            return sendRequest(MessageTypes.RP_REGISTER, data);
        } catch (Exception e) {
            System.err.println("❌ 发送RP注册请求失败: " + e.getMessage());
            return createErrorResponse("RP注册请求失败: " + e.getMessage());
        }
    }
    
    /**
     * 发送RP登录请求
     */
    public NetworkMessage sendRPLoginRequest(String username, String password) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("username", username);
            data.put("password", password);
            return sendRPRequest(MessageTypes.RP_LOGIN_REQUEST, data);
        } catch (Exception e) {
            System.err.println("❌ 发送RP登录请求失败: " + e.getMessage());
            return createErrorResponse("RP登录请求失败: " + e.getMessage());
        }
    }
    
    /**
     * 发送Token验证请求到RP
     */
    public NetworkMessage sendTokenVerifyRequest(String jwtToken) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("jwtToken", jwtToken);
            return sendRPRequest(MessageTypes.TOKEN_VERIFY_REQUEST, data);
        } catch (Exception e) {
            System.err.println("❌ 发送Token验证请求失败: " + e.getMessage());
            return createErrorResponse("Token验证请求失败: " + e.getMessage());
        }
    }
    
    /**
     * 发送RP证书请求
     */
    public NetworkMessage sendRPCertRequest() {
        try {
            Map<String, Object> data = new HashMap<>();
            return sendRPRequest(MessageTypes.RP_CERT_REQUEST, data);
        } catch (Exception e) {
            System.err.println("❌ 发送RP证书请求失败: " + e.getMessage());
            return createErrorResponse("RP证书请求失败: " + e.getMessage());
        }
    }

    /**
     * 请求指定 serverId 的 UserID OPRF 份额 b_i
     */
    public NetworkMessage sendUserIdOPRFShareRequestToServerId(int serverId, String blindedPointHex) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("blindedPoint", blindedPointHex);

            String requestId = generateRequestId();
            NetworkMessage request = new NetworkMessage(MessageTypes.USERID_OPRF_REQUEST, requestId, data);

            int serverPort = BASE_PORT + (serverId - 1);
            try (Socket socket = new Socket()) {
                socket.connect(new java.net.InetSocketAddress(SERVER_HOST, serverPort), CONNECTION_TIMEOUT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(request);
                out.flush();
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                return (NetworkMessage) in.readObject();
            }
        } catch (Exception e) {
            return createErrorResponse("请求UserID OPRF到 server " + serverId + " 失败: " + e.getMessage());
        }
    }

    /**
     * 解析 USERID_OPRF_RESPONSE 的份额列表（单返回）
     */
    public Pair<Integer, String> deserializeUserIdOPRFShare(NetworkMessage response) {
        if (response.getData() != null && Boolean.TRUE.equals(response.getData().get("success"))) {
            int serverId = Integer.parseInt((String) response.getData().get("serverId"));
            String ecPointHex = (String) response.getData().get("ecPoint");
            return Pair.of(serverId, ecPointHex);
        }
        return null;
    }
    
    /**
     * 发送网络请求的通用方法，随机选择一个服务器
     */
    private NetworkMessage sendRequest(String messageType, Map<String, Object> data) {
        String requestId = generateRequestId();
        NetworkMessage request = new NetworkMessage(messageType, requestId, data);
        
        // 随机选择一个服务器端口（单份额请求时可用）
        int serverPort = BASE_PORT + random.nextInt(NUM_SERVERS);
        
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(SERVER_HOST, serverPort), CONNECTION_TIMEOUT);
            
            // 发送请求
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(request);
            out.flush();
            
            // 接收响应
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            NetworkMessage response = (NetworkMessage) in.readObject();
            
            System.out.println("✅ 网络请求发送成功: " + messageType + " (服务器端口: " + serverPort + ")");
            return response;
            
        } catch (Exception e) {
            System.err.println("❌ 网络通信失败 (端口 " + serverPort + "): " + e.getMessage());
            return createErrorResponse("网络通信失败: " + e.getMessage());
        }
    }

    /**
     * 向给定serverId请求本地token share
     */
    public NetworkMessage sendTokenShareRequestToServerId(int serverId, byte[] userID, String blindedPointHex, long startTimeSec, Map<String, Object> info) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("userID", CryptoUtil.bytesToHex(userID));
            data.put("blindedPoint", blindedPointHex);
            data.put("startTimeSec", startTimeSec);
            data.put("info", info);

            String requestId = generateRequestId();
            NetworkMessage request = new NetworkMessage(MessageTypes.TOKEN_REQUEST, requestId, data);

            int serverPort = BASE_PORT + (serverId - 1);
            try (Socket socket = new Socket()) {
                socket.connect(new java.net.InetSocketAddress(SERVER_HOST, serverPort), CONNECTION_TIMEOUT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(request);
                out.flush();
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                return (NetworkMessage) in.readObject();
            }
        } catch (Exception e) {
            return createErrorResponse("请求server " + serverId + " 失败: " + e.getMessage());
        }
    }
    
    /**
     * 发送RP请求的专用方法
     */
    private NetworkMessage sendRPRequest(String messageType, Map<String, Object> data) {
        String requestId = generateRequestId();
        NetworkMessage request = new NetworkMessage(messageType, requestId, data);
        
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(SERVER_HOST, RP_SERVER_PORT), CONNECTION_TIMEOUT);
            
            // 发送请求
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(request);
            out.flush();
            
            // 接收响应
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            NetworkMessage response = (NetworkMessage) in.readObject();
            
            System.out.println("✅ RP请求发送成功: " + messageType + " (RP端口: " + RP_SERVER_PORT + ")");
            return response;
            
        } catch (Exception e) {
            System.err.println("❌ RP通信失败 (端口 " + RP_SERVER_PORT + "): " + e.getMessage());
            return createErrorResponse("RP通信失败: " + e.getMessage());
        }
    }
    
    /**
     * 序列化密钥份额列表
     */
    private List<Map<String, String>> serializeKeyShares(List<Pair<Integer, BigInteger>> keyShares) {
        List<Map<String, String>> result = new ArrayList<>();
        for (Pair<Integer, BigInteger> share : keyShares) {
            Map<String, String> shareData = new HashMap<>();
            shareData.put("serverId", String.valueOf(share.getFirst()));
            shareData.put("keyValue", share.getSecond().toString(16));
            result.add(shareData);
        }
        return result;
    }
    
    /**
     * 序列化服务器存储记录
     */
    private List<Map<String, String>> serializeServerStoreRecord(List<Pair<byte[], byte[]>> records) {
        List<Map<String, String>> result = new ArrayList<>();
        for (Pair<byte[], byte[]> record : records) {
            Map<String, String> recordData = new HashMap<>();
            recordData.put("lookupKey", CryptoUtil.bytesToHex(record.getFirst()));
            recordData.put("symmetricKey", CryptoUtil.bytesToHex(record.getSecond()));
            result.add(recordData);
        }
        return result;
    }
    
    /**
     * 反序列化令牌份额响应
     */
    public List<Pair<Integer, Pair<String, String>>> deserializeTokenShares(NetworkMessage response) {
        List<Pair<Integer, Pair<String, String>>> result = new ArrayList<>();
        
        if (response.getData() != null && response.getData().containsKey("tokenShares")) {
            List<Map<String, Object>> sharesData = (List<Map<String, Object>>) response.getData().get("tokenShares");
            
            for (Map<String, Object> shareData : sharesData) {
                int serverId = Integer.parseInt((String) shareData.get("serverId"));
                String encryptedToken = (String) shareData.get("encryptedToken");
                String ecPointHex = (String) shareData.get("ecPoint");
                
                result.add(Pair.of(serverId, Pair.of(encryptedToken, ecPointHex)));
            }
        }
        
        return result;
    }
    
    /**
     * 反序列化RP注册响应
     */
    @SuppressWarnings("unchecked")
    public Pair<String, String> deserializeRPRegisterResponse(NetworkMessage response) {
        if (response.getData() != null) {
            String identityHex = (String) response.getData().get("identity");
            String signatureHex = (String) response.getData().get("signature");
            return Pair.of(identityHex, signatureHex);
        }
        return null;
    }
    
    /**
     * 生成请求ID
     */
    private String generateRequestId() {
        return "req_" + System.currentTimeMillis() + "_" + random.nextInt(10000);
    }
    
    /**
     * 创建错误响应
     */
    private NetworkMessage createErrorResponse(String errorMessage) {
        Map<String, Object> errorData = new HashMap<>();
        errorData.put("error", errorMessage);
        return new NetworkMessage(MessageTypes.ERROR_RESPONSE, generateRequestId(), errorData);
    }
    
    /**
     * 检查响应是否成功
     */
    public boolean isSuccessResponse(NetworkMessage response) {
        return response != null && !MessageTypes.ERROR_RESPONSE.equals(response.getMessageType());
    }
    
    /**
     * 获取错误消息
     */
    public String getErrorMessage(NetworkMessage response) {
        if (response != null && response.getData() != null) {
            return (String) response.getData().get("error");
        }
        return "未知错误";
    }
}
