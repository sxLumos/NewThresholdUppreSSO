package network;

import config.SystemConfig;
import utils.CryptoUtil;
import utils.Pair;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 客户端网络管理器，负责与服务器进行网络通信
 */
public class ClientNetworkManager {
    private static final String SERVER_HOST = SystemConfig.SERVER_HOST;
    private static final int BASE_PORT = SystemConfig.BASE_PORT;
    private static final int RP_SERVER_PORT = SystemConfig.RP_SERVER_PORT; // RP服务器端口
    private static final int CONNECTION_TIMEOUT = SystemConfig.CONNECTION_TIMEOUT_MS; // 5秒超时
    // --- START: 添加用于测量通信代价的成员 ---
    private final AtomicLong totalBytesSent = new AtomicLong(0);
    private final AtomicLong totalBytesReceived = new AtomicLong(0);
    // --- END: 添加成员 ---
    
    private final Random random;
    
    public ClientNetworkManager() {
        this.random = new Random();
    }
    /**
     * 重置通信代价计数器。
     */
    public void resetCounters() {
        totalBytesSent.set(0);
        totalBytesReceived.set(0);
    }

    /**
     * 获取发送的总字节数。
     */
    public long getTotalBytesSent() {
        return totalBytesSent.get();
    }

    /**
     * 获取接收的总字节数。
     */
    public long getTotalBytesReceived() {
        return totalBytesReceived.get();
    }

    /**
     * [重构后] 所有网络请求的核心执行方法。
     * 在这里统一处理Socket通信和通信代价的测量。
     *
     * @param host    目标主机
     * @param port    目标端口
     * @param request 要发送的NetworkMessage对象
     * @return 从服务器接收到的NetworkMessage对象，或在失败时返回一个错误响应
     */
    private NetworkMessage executeRequest(String host, int port, NetworkMessage request) {
        // 1. 测量请求(Request)对象的大小
        long requestSize = getObjectSize(request);
        totalBytesSent.addAndGet(requestSize);

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), CONNECTION_TIMEOUT);

            // 发送请求
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(request);
            out.flush();

            // 接收响应
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            NetworkMessage response = (NetworkMessage) in.readObject();

            // 2. 测量响应(Response)对象的大小
            long responseSize = getObjectSize(response);
            totalBytesReceived.addAndGet(responseSize);

            return response;

        } catch (Exception e) {
            // 注意：客户端本地创建的错误响应不计入通信代价
            return createErrorResponse("网络通信失败 (" + host + ":" + port + "): " + e.getMessage());
        }
    }

    /**
     * [辅助方法] 通过将对象序列化到字节数组来计算其大小。
     * @param obj 需要计算大小的可序列化对象。
     * @return 对象的字节大小，如果序列化失败则返回0。
     */
    private long getObjectSize(Serializable obj) {
        if (obj == null) {
            return 0;
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            return baos.size();
        } catch (IOException e) {
            System.err.println("对象序列化失败，无法计算大小: " + e.getMessage());
            return 0;
        }
    }

    public NetworkMessage sendUserRegisterRequest(int serverId, BigInteger keyShareEnc,
                                                  BigInteger keyShareUserID,
                                                  Pair<byte[], byte[]> serverStoreRecord) {
        Map<String, Object> data = new HashMap<>();
        data.put("keyShareEnc", keyShareEnc.toString(16));
        data.put("keyShareUserID", keyShareUserID.toString(16));
        Map<String, String> recordData = new HashMap<>();
        recordData.put("lookupKey", CryptoUtil.bytesToHex(serverStoreRecord.getFirst()));
        recordData.put("symmetricKey", CryptoUtil.bytesToHex(serverStoreRecord.getSecond()));
        data.put("serverStoreRecord", recordData);

        NetworkMessage request = new NetworkMessage(MessageTypes.USER_REGISTER, generateRequestId(), data);
        int serverPort = BASE_PORT + (serverId - 1);

        return executeRequest(SERVER_HOST, serverPort, request);
    }

    public NetworkMessage sendTokenVerifyRequest(String jwtToken) {
        Map<String, Object> data = new HashMap<>();
        data.put("jwtToken", jwtToken);
        NetworkMessage request = new NetworkMessage(MessageTypes.TOKEN_VERIFY_REQUEST, generateRequestId(), data);
        return executeRequest(SERVER_HOST, RP_SERVER_PORT, request);
    }

    public NetworkMessage sendRPCertRequest() {
        NetworkMessage request = new NetworkMessage(MessageTypes.RP_CERT_REQUEST, generateRequestId(), new HashMap<>());
        return executeRequest(SERVER_HOST, RP_SERVER_PORT, request);
    }

    public NetworkMessage sendUserIdOPRFShareRequestToServerId(int serverId, String blindedPointHex) {
        Map<String, Object> data = new HashMap<>();
        data.put("blindedPoint", blindedPointHex);
        NetworkMessage request = new NetworkMessage(MessageTypes.USERID_OPRF_REQUEST, generateRequestId(), data);
        int serverPort = BASE_PORT + (serverId - 1);
        return executeRequest(SERVER_HOST, serverPort, request);
    }

    public NetworkMessage sendTokenShareRequestToServerId(int serverId, byte[] userID, String blindedPointHex, long startTimeSec, Map<String, Object> info) {
        Map<String, Object> data = new HashMap<>();
        data.put("userID", CryptoUtil.bytesToHex(userID));
        data.put("blindedPoint", blindedPointHex);
        data.put("startTimeSec", startTimeSec);
        data.put("info", info);
        NetworkMessage request = new NetworkMessage(MessageTypes.TOKEN_REQUEST, generateRequestId(), data);
        int serverPort = BASE_PORT + (serverId - 1);
        return executeRequest(SERVER_HOST, serverPort, request);
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
