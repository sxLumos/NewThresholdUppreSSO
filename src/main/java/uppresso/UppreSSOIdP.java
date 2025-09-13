package uppresso;

import org.bouncycastle.math.ec.ECPoint;
import server.idp.Certificate;
import server.interfaces.KeyGenerator;
import server.interfaces.TokenGenerator;
import utils.CryptoUtil;
import utils.Pair;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import network.NetworkMessage;

// A simple record to store user data together in the map.
record UserRecord(String hashedPassword, BigInteger iduScalar) {}

public class UppreSSOIdP {
    private final KeyGenerator keyGenerator;
    private final TokenGenerator tokenGenerator;

    // MODIFIED: The database now stores a UserRecord object.
    private static final Map<String, UserRecord> userDatabase = new HashMap<>();

    private static boolean isDatabaseLoaded = false;
    private static final String SHARED_DB_FILENAME = "idp_database.properties";

    // Lightweight network server (uppresso-only)
    private volatile boolean running = false;
    private ExecutorService threadPool;
    private int listenPort = 9100; // dedicated port for UppreSSO IdP demo
    private ServerSocket serverSocketRef;

    // Message types (scoped to uppresso flow)
    private static final String UP_REGISTER_USER = "UP_REGISTER_USER";
    private static final String UP_REQUEST_TOKEN = "UP_REQUEST_TOKEN";
    private static final String UP_REGISTER_RP = "UP_REGISTER_RP";

    /**
     * Initializes the Identity Provider.
     * It will either generate a new RSA key pair or load an existing one from a file.
     * It will also load the user database from a file.
     */
    public UppreSSOIdP() {
        // 1. Initialize the IdP's own cryptographic keys.
        //    Using `false` attempts to load existing keys first.
        this.keyGenerator = new RSAKeyGenerator(false);

        // 2. Initialize the JWT generator with the private key.
        Map<String, Object> keySet = this.keyGenerator.getKeySet();
        BigInteger n = (BigInteger) keySet.get(RSAKeyGenerator.PUBLIC_MODULUS);
        BigInteger d = (BigInteger) keySet.get(RSAKeyGenerator.PRIVATE_EXPONENT);
        this.tokenGenerator = new RSAJWTTokenGenerator(n, d);

        // 3. Load the user database from file once.
        if (!isDatabaseLoaded) {
            loadDatabase();
            isDatabaseLoaded = true;
        }
    }

    /**
     * Start a simple IdP server to handle UppreSSO requests over TCP using NetworkMessage.
     */
    public void startServer() {
        if (running) return;
        running = true;
        this.threadPool = Executors.newFixedThreadPool(8);
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(listenPort)) {
                this.serverSocketRef = serverSocket;
                System.out.println("🚀 UppreSSO IdP server started on port " + listenPort);
                while (running) {
                    try {
                        Socket client = serverSocket.accept();
                        threadPool.submit(() -> handleClient(client));
                    } catch (IOException e) {
                        if (running) System.err.println("❌ IdP accept failed: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                System.err.println("❌ Failed to start UppreSSO IdP server: " + e.getMessage());
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
            System.err.println("❌ IdP request handling error: " + e.getMessage());
        } finally {
            try { client.close(); } catch (IOException ignore) {}
        }
    }

    private NetworkMessage processRequest(NetworkMessage request) {
        try {
            String type = request.getMessageType();
            if (UP_REGISTER_USER.equals(type)) {
                String username = (String) request.getData().get("username");
                String hashedPassword = (String) request.getData().get("hashedPassword");
                registerUserAndGenerateID(username, hashedPassword);
                Map<String, Object> resp = new HashMap<>();
                resp.put("success", true);
                return new NetworkMessage(type + "_RESP", request.getRequestId(), resp);
            } else if (UP_REQUEST_TOKEN.equals(type)) {
                String username = (String) request.getData().get("username");
                String pidRpHex = (String) request.getData().get("pid_rp");
                ECPoint pidRp = CryptoUtil.decodePointFromHex(pidRpHex);
                String token = requestSsoToken(username, pidRp);
                Map<String, Object> resp = new HashMap<>();
                if (token != null) {
                    resp.put("success", true);
                    resp.put("jwt", token);
                } else {
                    resp.put("success", false);
                    resp.put("error", "Token issuance failed");
                }
                return new NetworkMessage(type + "_RESP", request.getRequestId(), resp);
            } else if (UP_REGISTER_RP.equals(type)) {
                Map<String, Object> resp = new HashMap<>();
                Map<String, Object> data = request.getData();
                String rpHost = (String) data.get("rpHost");
                if (rpHost == null || rpHost.isEmpty()) {
                    resp.put("success", false);
                    resp.put("error", "rpHost 不能为空");
                    return new NetworkMessage(type + "_RESP", request.getRequestId(), resp);
                }
                Pair<ECPoint, Certificate> pair = registerRP(rpHost);
                resp.put("success", true);
                resp.put("idRp", CryptoUtil.bytesToHex(pair.getFirst().getEncoded(true)));
                resp.put("signature", CryptoUtil.bytesToHex(pair.getSecond().getSignature()));
                try {
                    byte[] pkEncoded = this.keyGenerator.getPublicKey().getEncoded();
                    String pkBase64 = Base64.getEncoder().encodeToString(pkEncoded);
                    resp.put("publicKey", pkBase64);
                } catch (Exception ignore) {}
                return new NetworkMessage(type + "_RESP", request.getRequestId(), resp);
            }
            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("error", "Unknown message type: " + type);
            return new NetworkMessage("UP_ERROR", request.getRequestId(), err);
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("error", e.getMessage());
            return new NetworkMessage("UP_ERROR", request.getRequestId(), err);
        }
    }

    public Pair<ECPoint, Certificate> registerRP(String rpHost) {
        // 1. Randomly select r from Z_n.
        BigInteger r = CryptoUtil.randomScalar();

        // 2. Assign a unique point [r]G as the RP's identity (ID_RP).
        ECPoint idRp = CryptoUtil.GENERATOR.multiply(r).normalize();

//        System.out.println("IdP assigned a new identity to the RP: " + idRp.toString());

        // 3. 创建证书内容。
        // 我们使用点的十六进制表示作为要签名的内容。
        // 使用非压缩格式 getEncoded(false) 以获得更好的兼容性。
        String content = CryptoUtil.bytesToHex(idRp.getEncoded(true)) + ":" + rpHost;

        byte[] signature = this.keyGenerator.sign(content);

//        System.out.println("IdP has signed the certificate with its private key.");

        // 5. Create and return the certificate object.
        Certificate certRp = new Certificate(idRp, signature);
        return Pair.of(idRp, certRp);
    }

    // NEW METHOD: Register a user, generate their secret ID_U, and return it.
    public void registerUserAndGenerateID(String username, String hashedPassword) {
        if (userDatabase.containsKey(username)) {
            System.err.println("IdP: Registration failed. User '" + username + "' already exists.");
            // In a real system, you might just return the existing ID or an error.
            return ;
        }
        // 1. Generate a new, unique, secret scalar for the user's identity (ID_U)
        BigInteger iduScalar = CryptoUtil.randomScalar();

        // 2. Store the user's record
        UserRecord record = new UserRecord(hashedPassword, iduScalar);
        userDatabase.put(username, record);
        saveDatabase(); // Persist the change

        System.out.println("✅ IdP: User '" + username + "' registered successfully.");
    }

    // NEW METHOD: The main token issuance logic for the plain SSO flow.
    public String requestSsoToken(String username, ECPoint pid_rp) {
        // 1. Look up the user's record. In a real system, the user would be
        //    identified by a session cookie after authentication.
        UserRecord record = userDatabase.get(username);
        if (record == null) {
            System.err.println("❌ IdP: Token request failed. User '" + username + "' not found.");
            return null;
        }

        // 2. Get the user's secret ID_U scalar
        BigInteger iduScalar = record.iduScalar();

        // 3. Calculate the final PID_U = [ID_U] * PID_RP
        ECPoint pid_u = pid_rp.multiply(iduScalar).normalize();

        // 4. Prepare claims for the JWT
        Map<String, Object> claims = new HashMap<>();
        claims.put("pid_rp", Base64.getUrlEncoder().withoutPadding().encodeToString(pid_rp.getEncoded(true)));
        claims.put("pid_u", Base64.getUrlEncoder().withoutPadding().encodeToString(pid_u.getEncoded(true)));

        // 5. Generate and return the final signed JWT
        // The generateSsoToken method from our previous step is perfect for this.
        return generateSsoToken(username, claims);
    }

    /**
     * Authenticates a user against the stored credentials.
     * @param username The username.
     * @param hashedPassword The password to check.
     * @return true if the password is correct, false otherwise.
     */
    public boolean authenticateUser(String username, String hashedPassword) {
        UserRecord storeUserRecord = userDatabase.get(username);
        if (storeUserRecord == null) {
            return false; // User not found
        }
        return storeUserRecord.hashedPassword().equals(hashedPassword);
    }

    // MODIFIED: Update persistence logic to handle the new UserRecord structure.
    private static void saveDatabase() {
        Properties props = new Properties();
        userDatabase.forEach((username, record) -> {
            // Store as "{username}.hash=..." and "{username}.idu=..."
            props.setProperty(username + ".hash", record.hashedPassword());
            props.setProperty(username + ".idu", record.iduScalar().toString(16));
        });
        // ... rest of save logic is the same ...
    }

    /**
     * Generates a signed JWT for an authenticated user.
     * @param username The username to include in the token.
     * @param customClaims A map of any additional custom data to include in the token.
     * @return A signed JWT string, or null if the user cannot be authenticated.
     */
    public String generateSsoToken(String username, Map<String, Object> customClaims) {
        // In a real flow, you would authenticate first. Here we assume it's done.
        System.out.println("▶️ Generating SSO Token for user '" + username + "'...");

        long startTimeSec = System.currentTimeMillis() / 1000L;

        // Prepare claims. We will set the 'sub' (subject) claim to the username.
        Map<String, Object> allClaims = (customClaims != null) ? new HashMap<>(customClaims) : new HashMap<>();
        allClaims.put("sub", username);

        try {
            return this.tokenGenerator.generateToken(startTimeSec, allClaims);
        } catch (Exception e) {
            System.err.println("❌ Error generating token: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Returns the public key of the IdP, so others can verify its tokens.
     */
    public PublicKey getPublicKey() {
        return this.keyGenerator.getPublicKey();
    }

    // --- Private Helper Methods for Persistence and Hashing ---

    private static void loadDatabase() {
        File dbFile = new File(SHARED_DB_FILENAME);
        if (!dbFile.exists()) {
            System.out.println("▶️ User database file not found, will create a new one on first save.");
            return;
        }
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(dbFile)) {
            props.load(fis);
            props.forEach((key, value) -> userDatabase.put((String) key, (UserRecord) value));
            System.out.println("✅ User database loaded from " + SHARED_DB_FILENAME);
        } catch (IOException e) {
            System.err.println("❌ ERROR: Failed to load user database: " + e.getMessage());
        }
    }
}