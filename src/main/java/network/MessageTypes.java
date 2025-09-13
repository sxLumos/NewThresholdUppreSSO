package network;

/**
 * 定义所有网络消息类型常量
 */
public class MessageTypes {
    
    // 客户端到服务器的消息类型
    public static final String USER_REGISTER = "USER_REGISTER";
    public static final String USER_LOGIN = "USER_LOGIN";
    public static final String TOKEN_REQUEST = "TOKEN_REQUEST";
    public static final String RP_REGISTER = "RP_REGISTER";
    
    // 客户端到RP服务器的消息类型
    public static final String RP_LOGIN_REQUEST = "RP_LOGIN_REQUEST";
    public static final String TOKEN_VERIFY_REQUEST = "TOKEN_VERIFY_REQUEST";
    public static final String RP_CERT_REQUEST = "RP_CERT_REQUEST";
    
    // 服务器到客户端的响应类型
    public static final String REGISTER_RESPONSE = "REGISTER_RESPONSE";
    public static final String LOGIN_RESPONSE = "LOGIN_RESPONSE";
    public static final String TOKEN_RESPONSE = "TOKEN_RESPONSE";
    public static final String RP_REGISTER_RESPONSE = "RP_REGISTER_RESPONSE";
    
    // RP服务器到客户端的响应类型
    public static final String RP_LOGIN_RESPONSE = "RP_LOGIN_RESPONSE";
    public static final String TOKEN_VERIFY_RESPONSE = "TOKEN_VERIFY_RESPONSE";
    public static final String RP_CERT_RESPONSE = "RP_CERT_RESPONSE";
    
    // UserID OPRF
    public static final String USERID_OPRF_REQUEST = "USERID_OPRF_REQUEST";
    public static final String USERID_OPRF_RESPONSE = "USERID_OPRF_RESPONSE";
    
    // 错误响应
    public static final String ERROR_RESPONSE = "ERROR_RESPONSE";
    
    // 内部服务器通信
    public static final String STORE_USER_DATA = "STORE_USER_DATA";
    public static final String RETRIEVE_USER_DATA = "RETRIEVE_USER_DATA";
    public static final String GENERATE_TOKEN_SHARE = "GENERATE_TOKEN_SHARE";
}
