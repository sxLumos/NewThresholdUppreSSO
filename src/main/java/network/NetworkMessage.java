package network;

import java.io.Serializable;
import java.util.Map;

/**
 * 网络消息基类，用于客户端和服务器之间的通信
 */
public class NetworkMessage implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String messageType;
    private String requestId;
    private Map<String, Object> data;
    private long timestamp;
    
    public NetworkMessage() {
        this.timestamp = System.currentTimeMillis();
    }
    
    public NetworkMessage(String messageType, String requestId, Map<String, Object> data) {
        this();
        this.messageType = messageType;
        this.requestId = requestId;
        this.data = data;
    }
    
    // Getters and Setters
    public String getMessageType() { return messageType; }
    public void setMessageType(String messageType) { this.messageType = messageType; }
    
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    
    public Map<String, Object> getData() { return data; }
    public void setData(Map<String, Object> data) { this.data = data; }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    @Override
    public String toString() {
        return String.format("NetworkMessage{type='%s', requestId='%s', timestamp=%d}", 
                           messageType, requestId, timestamp);
    }
}

