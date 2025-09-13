package uppresso;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.bouncycastle.math.ec.ECPoint;
import server.idp.Certificate;
import utils.CryptoUtil;
import utils.Pair;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import network.NetworkMessage;

public class UppreSSORP {
    private ECPoint identity; // ID_RP
    private Certificate certificate; // Cert_RP
    private PublicKey publicKey; // Cert_RP
    private String cachedPublicKeyBase64;
    private static final String FILE_NAME = "relying_party.properties";
    private String idpHost = "localhost";
    private int idpPort = 9100; // must match UppreSSOIdP.listenPort

    // RP server parameters
    private int rpListenPort = 9101;
    private volatile boolean running = false;
    private ExecutorService threadPool;
    private ServerSocket serverSocketRef;
    private static final String RP_HOST = "example.com";

    // Message types
    private static final String UP_RP_CERT_REQUEST = "UP_RP_CERT_REQUEST";
    private static final String UP_RP_CERT_RESPONSE = "UP_RP_CERT_RESPONSE";
    private static final String UP_RP_VERIFY_TOKEN_REQUEST = "UP_RP_VERIFY_TOKEN_REQUEST";
    private static final String UP_RP_VERIFY_TOKEN_RESPONSE = "UP_RP_VERIFY_TOKEN_RESPONSE";

    public void registerOverNetwork() {
        try (Socket socket = new Socket(idpHost, idpPort)) {
            String reqId = "rp_reg_" + System.currentTimeMillis();
            java.util.Map<String, Object> data = new java.util.HashMap<>();
            data.put("rpHost", RP_HOST);
            NetworkMessage req = new NetworkMessage("UP_REGISTER_RP", reqId, data);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(req);
            out.flush();
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            NetworkMessage resp = (NetworkMessage) in.readObject();
            if (resp.getData() != null && Boolean.TRUE.equals(resp.getData().get("success"))) {
                String idRpHex = (String) resp.getData().get("idRp");
                String sigHex = (String) resp.getData().get("signature");
                String publicKeyBase64 = (String) resp.getData().get("publicKey");
                this.cachedPublicKeyBase64 = publicKeyBase64;
                this.identity = CryptoUtil.decodePointFromHex(idRpHex);
                this.certificate = new Certificate(RP_HOST, this.identity, CryptoUtil.hexToBytes(sigHex));
                byte[] pkBytes = Base64.getDecoder().decode(publicKeyBase64);
                java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(pkBytes);
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
                this.publicKey = kf.generatePublic(spec);
//                this.saveStateToFile();
                // REQUIREMENT 1: RP verifies the certificate signature
                String content = idRpHex + ":" + RP_HOST;
                byte[] signature = CryptoUtil.hexToBytes(sigHex);
                if (RSAKeyGenerator.verify(content, signature, this.publicKey)) {
                    System.out.println("✅ RP successfully verified its new certificate from IdP.");
                } else {
                    System.err.println("❌ CRITICAL: RP failed to verify its new certificate. Aborting.");
                }
                System.out.println("✅ UppreSSO RP registered with IdP.");
            } else {
                System.err.println("RP register failed: " + (resp.getData() == null ? "no data" : resp.getData().get("error")));
            }
        } catch (Exception e) {
            System.err.println("RP registerOverNetwork error: " + e.getMessage());
        }
    }

    // ----------------- Lightweight RP server -----------------
    public void startServer() {
        if (running) return;
        running = true;
        this.threadPool = Executors.newFixedThreadPool(8);
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(rpListenPort)) {
                this.serverSocketRef = serverSocket;
                System.out.println("🚀 UppreSSO RP server started on port " + rpListenPort);
                while (running) {
                    try {
                        Socket client = serverSocket.accept();
                        threadPool.submit(() -> handleClient(client));
                    } catch (IOException e) {
                        if (running) System.err.println("❌ RP accept failed: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                System.err.println("❌ Failed to start UppreSSO RP server: " + e.getMessage());
            }
        }).start();
    }

    public void stopServer() {
        running = false;
        if (threadPool != null) threadPool.shutdown();
        if (serverSocketRef != null && !serverSocketRef.isClosed()) {
            try { serverSocketRef.close(); } catch (IOException ignore) {}
        }
    }

    private void handleClient(Socket client) {
        try (ObjectInputStream in = new ObjectInputStream(client.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream())) {
            NetworkMessage req = (NetworkMessage) in.readObject();
            NetworkMessage resp = processRequest(req);
            out.writeObject(resp);
            out.flush();
        } catch (Exception e) {
            System.err.println("❌ RP request handling error: " + e.getMessage());
        } finally {
            try { client.close(); } catch (IOException ignore) {}
        }
    }

    private NetworkMessage processRequest(NetworkMessage request) {
        try {
            String type = request.getMessageType();
            if (UP_RP_CERT_REQUEST.equals(type)) {
                Map<String, Object> resp = new HashMap<>();
                if (this.certificate == null || this.identity == null) {
                    // try load from file
                    try { this.loadStateFromFile(); } catch (IOException ignore) {}
                }
                if (this.certificate != null && this.identity != null) {
                    resp.put("success", true);
                    resp.put("identity", CryptoUtil.bytesToHex(this.identity.getEncoded(true)));
                    resp.put("signature", CryptoUtil.bytesToHex(this.certificate.getSignature()));
                    resp.put("rpHost", this.certificate.getRpHost());
                    if (this.cachedPublicKeyBase64 != null) {
                        resp.put("publicKey", this.cachedPublicKeyBase64);
                    }
                } else {
                    resp.put("success", false);
                    resp.put("error", "RP not registered");
                }
                return new NetworkMessage(UP_RP_CERT_RESPONSE, request.getRequestId(), resp);
            } else if (UP_RP_VERIFY_TOKEN_REQUEST.equals(type)) {
                String token = (String) request.getData().get("jwt");
                Map<String, Object> respData = new HashMap<>();
                try {
                    // Use the stored IdP Public Key to verify the token
                    DecodedJWT verifiedJwt = RSAJWTVerifier.verify(token, this.publicKey);
                    System.out.println("✅ RP successfully verified token for client.");
                    respData.put("success", true);
                    respData.put("message", "Token is valid.");
                    respData.put("issuer", verifiedJwt.getIssuer());
                    respData.put("subject", verifiedJwt.getSubject());
                    respData.put("issuedAt", verifiedJwt.getIssuedAt());
                    respData.put("expiresAt", verifiedJwt.getExpiresAt());

                    // 提取自定义声明
                    if (verifiedJwt.getClaim("pid_rp") != null) {
                        respData.put("pid_rp", verifiedJwt.getClaim("pid_rp").asString());
                    }
                    if (verifiedJwt.getClaim("pid_u") != null) {
                        respData.put("pid_u", verifiedJwt.getClaim("pid_u").asString());
                    }
                } catch (Exception e) {
                    System.err.println("❌ RP failed to verify token: " + e.getMessage());
                    respData.put("success", false);
                    respData.put("error", "Token verification failed: " + e.getMessage());
                }
                return new NetworkMessage(UP_RP_VERIFY_TOKEN_RESPONSE, request.getRequestId(), respData);
            }
            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("error", "Unknown RP message type: " + type);
            return new NetworkMessage("UP_RP_ERROR", request.getRequestId(), err);
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("error", e.getMessage());
            return new NetworkMessage("UP_RP_ERROR", request.getRequestId(), err);
        }
    }

    /**
     * [新增] 将 RP 的身份和证书保存到文件中。
     * 文件名将是 "rp_[RP名称].properties"。
     */
    public void saveStateToFile(){
        if (this.identity == null || this.certificate == null) {
            System.err.println("错误：RP尚未注册，无法保存状态。");
            return;
        }

        Properties props = new Properties();
        // 使用非压缩格式 getEncoded(false) 以获得更好的兼容性
        String idRpHex = CryptoUtil.bytesToHex(this.identity.getEncoded(true));
        String signatureHex = CryptoUtil.bytesToHex(this.certificate.getSignature());

        // 存储所有必要信息
        props.setProperty("rp.identity.hex", idRpHex);
        props.setProperty("cert.signature.hex", signatureHex);

        try (FileOutputStream fos = new FileOutputStream(FILE_NAME)) {
            props.store(fos, "Relying Party State");
            System.out.println("RP的状态已成功保存到文件: " + FILE_NAME);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Certificate getCertificate() {
        return this.certificate;
    }

    /**
     * [新增] 从文件中加载 RP 的身份和证书。
     * @return 如果加载成功，返回 true；否则返回 false。
     */
    public boolean loadStateFromFile() throws IOException {
        File file = new File(FILE_NAME);
        if (!file.exists()) {
            System.err.println("错误：未找到 RP的状态文件: " + FILE_NAME);
            return false;
        }

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(FILE_NAME)) {
            props.load(fis);

            // 读取并重建数据
            String idRpHex = props.getProperty("rp.identity.hex");
            String signatureHex = props.getProperty("cert.signature.hex");

            if (idRpHex == null || signatureHex == null) {
                System.err.println("错误：状态文件 " + FILE_NAME + " 中缺少必要信息。");
                return false;
            }

            // 解码并设置身份
            this.identity = CryptoUtil.decodePointFromHex(idRpHex);

            // 重建证书
            byte[] signature = CryptoUtil.hexToBytes(signatureHex);
            this.certificate = new Certificate(this.identity, signature);

            System.out.println("RP的状态已从文件 " + FILE_NAME + " 成功加载。");
            System.out.println("  - 加载的身份 (ID_RP): " + this.identity);
            System.out.println("  - 加载的证书: " + this.certificate);
            return true;
        }
    }
}
