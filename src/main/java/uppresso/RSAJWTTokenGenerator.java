package uppresso;

import org.json.simple.JSONObject;
import server.interfaces.TokenGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * A standard RSA JWT Token Generator.
 * It uses a complete RSA private key (n, d) to generate a fully signed and verifiable JWT.
 */
public class RSAJWTTokenGenerator implements TokenGenerator {
    private final BigInteger n; // RSA Modulus
    private final BigInteger d; // RSA Private Exponent

    /**
     * Constructor to initialize the generator with the full RSA private key.
     *
     * @param n The RSA modulus.
     * @param d The RSA private exponent.
     */
    public RSAJWTTokenGenerator(BigInteger n, BigInteger d) {
        this.n = n;
        this.d = d;
    }

    /**
     * Generates a complete, standard, signed JWT.
     * The signature is calculated using the full private key with the SHA256withRSA algorithm.
     *
     * @return A JWT string in the format "header.payload.signature".
     */
    @Override
    public String generateToken(long startTimeSec, Map<String, Object> info) {
        // 1. Build the Base64Url-encoded header and payload
        String base64UrlHeader = buildJWTHeader();
        String base64UrlPayload = buildJWTPayload(startTimeSec, info);

        // 2. Define the content that needs to be signed
        String contentToSign = base64UrlHeader + "." + base64UrlPayload;

        try {
            // 3. Reconstruct the PrivateKey object from n and d
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);
            PrivateKey rsaPrivateKey = keyFactory.generatePrivate(privateKeySpec);

            // 4. Use the standard Java Signature class to sign the content
            Signature rsaSign = Signature.getInstance("SHA256withRSA");
            rsaSign.initSign(rsaPrivateKey);
            rsaSign.update(contentToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = rsaSign.sign();

            // 5. Base64Url-encode the signature
            String base64UrlSignature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signatureBytes);

            // 6. Assemble and return the final JWT
            return contentToSign + "." + base64UrlSignature;

        } catch (Exception e) {
            // In a real application, more specific exception handling would be better.
            throw new RuntimeException("Failed to generate JWT signature", e);
        }
    }

    /**
     * Builds the JWT payload with standard claims.
     * @return A Base64Url-encoded string of the payload JSON.
     */
    private String buildJWTPayload(long startTimeSec, Map<String, Object> infos) {
        JSONObject json = new JSONObject();
        // Add standard JWT claims
        json.put("iss", "MyIssuer"); // Changed from "ThresholdIdP"
        json.put("sub", "service-account-1");
        json.put("iat", startTimeSec);
        json.put("exp", startTimeSec + 3600); // Expires in 1 hour
        json.put("aud", "MyAPI");

        // Add custom claims from the infos map
        if (infos != null) {
            json.putAll(infos);
        }

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