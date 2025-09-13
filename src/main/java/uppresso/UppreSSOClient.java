package uppresso;


import org.bouncycastle.math.ec.ECPoint;
import utils.CryptoUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.net.Socket;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;

import network.NetworkMessage;
import utils.SimpleBenchmark;

public class UppreSSOClient {
    private final String username;
    private final String password;
    private String idpHost = "localhost";
    private int idpPort = 9100; // must match UppreSSOIdP.listenPort
    private String rpHost = "localhost";
    private int rpPort = 9101; // must match UppreSSORP.rpListenPort
    private String jwtToken;
    private static final int benchmarkRuns = 10;

    // --- START: Added for communication cost measurement ---
    private final AtomicLong totalBytesSent = new AtomicLong(0);
    private final AtomicLong totalBytesReceived = new AtomicLong(0);
    // --- END: Added members ---

    public static void main(String[] args) {
        UppreSSOClient client = new UppreSSOClient("shenxin", "123456");

        // 1. Reset counters before all benchmarks
        client.resetCommunicationCounters();

        // 2. Run benchmarks (communication cost is accumulated automatically)
        Runnable userRegisterRequestTask = client::register;
        Runnable userTokenRequestTask = () -> {
            client.login();
            client.requestToken();
        };
        Runnable userVerifyTask = client::verify;
        double a = SimpleBenchmark.getAverageTime(benchmarkRuns, userRegisterRequestTask);
        double b = SimpleBenchmark.getAverageTime(benchmarkRuns, userTokenRequestTask);
        double c = SimpleBenchmark.getAverageTime(benchmarkRuns, userVerifyTask);
        System.out.printf("User注册耗时: %.0f ms\n", a);
        System.out.printf("User请求Token耗时: %.0f ms\n", b);
        System.out.printf("验证Token耗时: %.0f ms\n", c);

        // 3. Report the final average communication cost
        client.reportCommunicationCost();
    }

    public UppreSSOClient(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // --- START: Added communication measurement infrastructure ---

    /**
     * Resets the communication counters to zero.
     */
    public void resetCommunicationCounters() {
        totalBytesSent.set(0);
        totalBytesReceived.set(0);
    }

    /**
     * Prints the final communication cost statistics.
     */
    public void reportCommunicationCost() {
        long totalSent = totalBytesSent.get();
        long totalReceived = totalBytesReceived.get();
        long totalComm = totalSent + totalReceived;

        // Divide by benchmarkRuns to get the average cost for one complete user flow
        double avgSentKB = (double) totalSent / benchmarkRuns / 1024.0;
        double avgReceivedKB = (double) totalReceived / benchmarkRuns / 1024.0;
        double avgTotalCommKB = (double) totalComm / benchmarkRuns / 1024.0;

        System.out.printf(
                "\n=======================================================\n" +
                        "      平均通信代价 (单次完整流程: 注册+登录+验证)\n" +
                        "-------------------------------------------------------\n" +
                        "  - 平均发送量: %.2f KB\n" +
                        "  - 平均接收量: %.2f KB\n" +
                        "  - 平均总通信量: %.2f KB\n" +
                        "=======================================================\n",
                avgSentKB,
                avgReceivedKB,
                avgTotalCommKB
        );
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
     * Centralized method to execute a network request and measure its cost.
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
            java.util.Map<String, Object> errorData = new java.util.HashMap<>();
            errorData.put("success", false);
            errorData.put("error", "Network error: " + e.getMessage());
            return new NetworkMessage("ERROR", request.getRequestId(), errorData);
        }
    }

    // --- END: Added infrastructure ---


    public void register() {
        System.out.println("\n▶️ Client starting registration for user '" + this.username + "'...");
        String hashedPassword = hash(this.password);
        String reqId = "up_reg_" + System.currentTimeMillis();
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        data.put("username", this.username);
        data.put("hashedPassword", hashedPassword);
        NetworkMessage req = new NetworkMessage("UP_REGISTER_USER", reqId, data);

        // Refactored to use the central executeRequest method
        NetworkMessage resp = executeRequest(idpHost, idpPort, req);

        if (resp.getData() == null || !Boolean.TRUE.equals(resp.getData().get("success"))) {
            System.err.println("❌ Registration failed: " + (resp.getData() == null ? "no data" : resp.getData().get("error")));
        }
    }
    public void login() {
        System.out.println("\n▶️ Client starting login for user '" + this.username + "'...");
        String hashedPassword = hash(this.password);
        String reqId = "up_reg_" + System.currentTimeMillis();
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        data.put("username", this.username);
        data.put("hashedPassword", hashedPassword);
        NetworkMessage req = new NetworkMessage("UP_AUTHENTICATE_USER", reqId, data);

        // Refactored to use the central executeRequest method
        NetworkMessage resp = executeRequest(idpHost, idpPort, req);

        if (resp.getData() == null || !Boolean.TRUE.equals(resp.getData().get("success"))) {
            System.err.println("❌ Login failed: " + (resp.getData() == null ? "no data" : resp.getData().get("error")));
        }
    }

    public void requestToken() {
        System.out.println("\n▶️ Client starting login for user '" + this.username + "'...");
        ECPoint id_rp;

        // Step 1: Obtain RP certificate
        try {
            String reqIdCert = "up_rp_cert_" + System.currentTimeMillis();
            NetworkMessage reqCert = new NetworkMessage("UP_RP_CERT_REQUEST", reqIdCert, new java.util.HashMap<>());

            // Refactored to use the central executeRequest method
            NetworkMessage respCert = executeRequest(rpHost, rpPort, reqCert);

            if (respCert.getData() != null && Boolean.TRUE.equals(respCert.getData().get("success"))) {
                String idRpHex = (String) respCert.getData().get("identity");
                id_rp = CryptoUtil.decodePointFromHex(idRpHex);
                // Other verification logic can remain if needed...
            } else {
                System.err.println("❌ Failed to fetch RP certificate: " + (respCert.getData() == null ? "no data" : respCert.getData().get("error")));
                return;
            }
        } catch (Exception e) {
            System.err.println("❌ RP certificate processing error: " + e.getMessage());
            return;
        }

        // Step 2: Request token from IdP
        BigInteger t = CryptoUtil.randomScalar();
        ECPoint pid_rp = id_rp.multiply(t).normalize();
        String reqIdToken = "up_reqtok_" + System.currentTimeMillis();
        java.util.Map<String, Object> dataToken = new java.util.HashMap<>();
        dataToken.put("username", this.username);
        dataToken.put("pid_rp", CryptoUtil.bytesToHex(pid_rp.getEncoded(true)));
        NetworkMessage reqToken = new NetworkMessage("UP_REQUEST_TOKEN", reqIdToken, dataToken);

        // Refactored to use the central executeRequest method
        NetworkMessage respToken = executeRequest(idpHost, idpPort, reqToken);

        if (respToken.getData() != null && Boolean.TRUE.equals(respToken.getData().get("success"))) {
            jwtToken = (String) respToken.getData().get("jwt");
        } else {
            System.err.println("❌ Token request failed: " + (respToken.getData() == null ? "no data" : respToken.getData().get("error")));
        }
    }

    private void verify() {
        if (jwtToken == null) {
            System.err.println("❌ Verify failed: No token to verify.");
            return;
        }
        System.out.println("   - Step 4: Sending token to RP for verification...");
        boolean isTokenValid = verifyTokenAtRP(jwtToken);
        if (!isTokenValid) {
            System.err.println("❌ RP reported that the token is invalid.");
            return;
        }
        System.out.println("✅ RP confirmed token is valid. Login successful!");
    }

    private boolean verifyTokenAtRP(String jwtToken) {
        String reqId = "up_rp_verify_tok_" + System.currentTimeMillis();
        java.util.Map<String, Object> data = new java.util.HashMap<>();
        data.put("jwt", jwtToken);
        NetworkMessage req = new NetworkMessage("UP_RP_VERIFY_TOKEN_REQUEST", reqId, data);

        // Refactored to use the central executeRequest method
        NetworkMessage resp = executeRequest(rpHost, rpPort, req);

        return resp.getData() != null && Boolean.TRUE.equals(resp.getData().get("success"));
    }

    private String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}