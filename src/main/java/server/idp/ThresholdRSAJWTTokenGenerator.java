package server.idp;

import org.json.simple.JSONObject;
import server.interfaces.TokenGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

public class ThresholdRSAJWTTokenGenerator implements TokenGenerator {
    private final BigInteger privateKeyShare; // d_i
    private final BigInteger n; // RSA modulus
    private final int sid;

    /**
     * Constructor to initialize the generator with its cryptographic material.
     *
     * @param privateKeyShare The server's share of the private key (d_i).
     * @param n The RSA modulus (n), which is public.
     */
    public ThresholdRSAJWTTokenGenerator(BigInteger n, BigInteger privateKeyShare, int sid) {
        this.privateKeyShare = privateKeyShare;
        this.n = n;
        this.sid = sid;
    }

    /**
     * Generate a signature share s_i = H(m)^{d_i} mod n for arbitrary content.
     * Returns the raw BigInteger share value.
     */
    public BigInteger generateSignatureShare(byte[] contentBytes) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(contentBytes);
        BigInteger messageHash = new BigInteger(1, hash);
        return messageHash.modPow(privateKeyShare, n);
    }

    /**
     * Generates a partially-signed JWT, also known as a "token share".
     * The signature is calculated using the private key share.
     * s_i = h^(d_i) mod n
     *
     * @return A string in the format "header.payload.partial_signature".
     */
    @Override
    public String generateToken(long startTimeSec, Map<String, Object> info) {
        // 1. Build the Base64Url-encoded header and payload
        String base64UrlHeader = buildJWTHeader();
        String base64UrlPayload = buildJWTPayload(startTimeSec, info);

        // 2. Define the content that needs to be signed
        String contentToSign = base64UrlHeader + "." + base64UrlPayload;

        try {
            // 3. Hash the content using SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(contentToSign.getBytes(StandardCharsets.UTF_8));
            BigInteger messageHash = new BigInteger(1, hash);

            // 4. Calculate the partial signature: s_i = messageHash^(d_i) mod n
            BigInteger partialSignature = messageHash.modPow(privateKeyShare, n);

            // 5. Base64Url-encode the partial signature
            String base64UrlSignature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(partialSignature.toByteArray());

            // 6. Assemble and return the final token share
            return contentToSign + "." + base64UrlSignature;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Builds the JWT payload with standard claims.
     * @return A Base64Url-encoded string of the payload JSON.
     */
    private String buildJWTPayload(long startTimeSec, Map<String, Object> infos) {
        JSONObject json = new JSONObject();
        // 1. 添加标准的、固定的 JWT Claim
        json.put("iss", "ThresholdIdP");
        json.put("sub", "service-account-1");
        json.put("iat", startTimeSec); // 签发时间
        json.put("exp", startTimeSec + 3600); // 过期时间，例如设置为1小时后
        json.put("aud", "MyAPI");

        // 2. [新增] 遍历 infos Map，将所有键值对添加为自定义 Claim
        if (infos != null) {
            // putAll 方法可以高效地将一个 Map 的所有内容复制到另一个 Map
            json.putAll(infos);
        }

        // 注意：如果 infos 中包含与标准 Claim（如 "iss", "exp"）相同的键，
        // json.putAll 的行为通常会用 infos 中的值覆盖标准值。

        String payloadJson = json.toJSONString();
        byte[] payloadBytes = payloadJson.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes);
    }

    /**
     * Builds the JWT header.
     * @return A Base64Url-encoded string of the header JSON.
     */
    private String buildJWTHeader() {
        JSONObject json = new JSONObject();
        json.put("alg", "RS256");
        json.put("typ", "JWT");

        String headerJson = json.toJSONString();
        byte[] headerBytes = headerJson.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(headerBytes);
    }
}

