package uppresso;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.bouncycastle.math.ec.ECPoint;
import server.idp.Certificate;
import utils.CryptoUtil;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
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
import java.util.concurrent.atomic.AtomicLong;

import network.NetworkMessage;

public class UppreSSORP {
    private ECPoint identity; // ID_RP
    private Certificate certificate; // Cert_RP
    private PublicKey publicKey; // Cert_RP
    private String cachedPublicKeyBase64;
//    private static final String FILE_NAME = "relying_party.properties";
    private String idpHost = "localhost";
    private int idpPort = 9100; // must match UppreSSOIdP.listenPort

    // RP server parameters
    private int rpListenPort = 9101;
    private volatile boolean running = false;
    private ExecutorService threadPool;
    private ServerSocket serverSocketRef;
    private static final String RP_HOST = "example.com";

    // --- START: Added for communication cost measurement ---
    private final AtomicLong totalBytesSent = new AtomicLong(0);
    private final AtomicLong totalBytesReceived = new AtomicLong(0);
    // --- END: Added members ---

    // Message types
    private static final String UP_RP_CERT_REQUEST = "UP_RP_CERT_REQUEST";
    private static final String UP_RP_CERT_RESPONSE = "UP_RP_CERT_RESPONSE";
    private static final String UP_RP_VERIFY_TOKEN_REQUEST = "UP_RP_VERIFY_TOKEN_REQUEST";
    private static final String UP_RP_VERIFY_TOKEN_RESPONSE = "UP_RP_VERIFY_TOKEN_RESPONSE";

    // --- START: Added communication measurement infrastructure ---

    /**
     * Resets the communication counters to zero.
     */
    public void resetCommunicationCounters() {
        totalBytesSent.set(0);
        totalBytesReceived.set(0);
    }

    public long getTotalBytesSent() {
        return totalBytesSent.get();
    }

    public long getTotalBytesReceived() {
        return totalBytesReceived.get();
    }

    /**
     * Calculates the size of a serializable object in bytes.
     */
    private long getObjectSize(Serializable obj) {
        if (obj == null) return 0;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            return baos.size();
        } catch (IOException e) {
            System.err.println("Error calculating object size: " + e.getMessage());
            return 0;
        }
    }

    /**
     * Centralized method to execute an outgoing network request and measure its cost.
     */
    private NetworkMessage executeRequest(String host, int port, NetworkMessage request) {
        totalBytesSent.addAndGet(getObjectSize(request));
        try (Socket socket = new Socket(host, port)) {
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(request);
            out.flush();

            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            NetworkMessage response = (NetworkMessage) in.readObject();

            totalBytesReceived.addAndGet(getObjectSize(response));
            return response;
        } catch (Exception e) {
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("success", false);
            errorData.put("error", "Network error: " + e.getMessage());
            return new NetworkMessage("ERROR", request.getRequestId(), errorData);
        }
    }
    // --- END: Added infrastructure ---

    /**
     * [Refactored] This method now uses the central executeRequest helper.
     */
    public void registerOverNetwork() {
        try {
            String reqId = "rp_reg_" + System.currentTimeMillis();
            Map<String, Object> data = new HashMap<>();
            data.put("rpHost", RP_HOST);
            NetworkMessage req = new NetworkMessage("UP_REGISTER_RP", reqId, data);

            // The original socket logic is replaced with this single call
            NetworkMessage resp = executeRequest(idpHost, idpPort, req);

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

                // Verification logic remains
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

    // ----------------- Lightweight RP server (No changes below this line) -----------------
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

    // ... [ The rest of the file (processRequest, saveStateToFile, etc.) remains unchanged ] ...
    private NetworkMessage processRequest(NetworkMessage request) {
        try {
            String type = request.getMessageType();
            if (UP_RP_CERT_REQUEST.equals(type)) {
                Map<String, Object> resp = new HashMap<>();
                if (this.certificate == null || this.identity == null) {
                    throw new RuntimeException("RP未注册");
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

    public Certificate getCertificate() {
        return this.certificate;
    }
}