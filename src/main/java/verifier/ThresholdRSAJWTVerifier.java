package verifier;


import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.bouncycastle.math.ec.ECPoint;
import utils.Pair;
import utils.SymmetricEncryptor;
import verifier.interfaces.JWTVerifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


public class ThresholdRSAJWTVerifier implements JWTVerifier {
    /**
     * Combines multiple partially-signed JWTs into a single, complete JWT.
     *
     * @param partialJwts A map from server ID to the partially-signed JWT string.
     * @return The final, combined JWT string.
     */
    public static String combineJwtShares(List<byte[]> keys, List<Pair<Integer, Pair<String, ECPoint>>> partialJwts, PublicKey publicKey, int threshold) {
        if (partialJwts.size() < threshold) {
            throw new IllegalArgumentException("Not enough partial JWTs to meet the threshold.");
        }
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of RSAPublicKey.");
        }

        // 从RSAPublicKey中获取模数n
        BigInteger n = ((RSAPublicKey) publicKey).getModulus();

        // A simple record or class to hold the serverId and signature value together.

        List<PartialSignature> partialSignatures = new ArrayList<>();
        String finalHeader = null;
        String finalPayload = null;
        for (int i = 0;i < partialJwts.size() && i < threshold;i ++ ) {
            int sid = partialJwts.get(i).getFirst();
            String partialJwt = partialJwts.get(i).getSecond().getFirst();

            // 2. Decode the Base64 string back to bytes
            byte[] encryptedTokenBytes = Base64.getDecoder().decode(partialJwt);
            // 4. Decrypt the data
            byte[] decryptedTokenBytes = SymmetricEncryptor.decrypt(encryptedTokenBytes, keys.get(sid - 1));
            String originalTokenShare = new String(decryptedTokenBytes, StandardCharsets.UTF_8);

//            System.out.println("✅ Decryption successful!");
//            System.out.println("   - Original Token Payload: " + new String(Base64.getDecoder().decode(originalTokenShare.split("\\.")[1])));
            String[] parts = originalTokenShare.split("\\.");
            if (finalHeader == null) {
                finalHeader = parts[0];
                finalPayload = parts[1];
            }
            BigInteger sigValue = new BigInteger(1, Base64.getUrlDecoder().decode(parts[2]));
            partialSignatures.add(new PartialSignature(sid, sigValue));
        }

        BigInteger finalSignatureValue = combineSignatures(partialSignatures, n, threshold);
        String finalSignatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(finalSignatureValue.toByteArray());

        return finalHeader + "." + finalPayload + "." + finalSignatureBase64;
    }

    public static DecodedJWT verify(String token, PublicKey publicKey, int threshold) throws SignatureException {
        if (!(publicKey instanceof RSAPublicKey rsaPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of RSAPublicKey.");
        }

        try {
            BigInteger n = rsaPublicKey.getModulus();
            BigInteger e = rsaPublicKey.getPublicExponent();
            String[] parts = token.split("\\.");

            String content = parts[0] + "." + parts[1];
            BigInteger signature = new BigInteger(1, Base64.getUrlDecoder().decode(parts[2]));

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            BigInteger messageHash = new BigInteger(1, digest.digest(content.getBytes(StandardCharsets.UTF_8)));

            // This is the core threshold verification logic
            boolean isValid = verifyThresholdSignature(messageHash, signature, n, e, threshold);

            if (!isValid) {
                throw new SignatureException("Threshold RSA signature verification failed.");
            }
            return JWT.decode(token);
        } catch (Exception e) {
            throw new SignatureException("Verification failed.", e);
        }
    }

    public static BigInteger combineSignatures(List<PartialSignature> partials, BigInteger n, int t) {
        BigInteger delta = factorial(t);
        BigInteger combinedSignature = BigInteger.ONE;

        for (PartialSignature partial : partials) {
            BigInteger i = BigInteger.valueOf(partial.getServerId());
            // Calculate integer Lagrange coefficient lambda_i for point 0
            BigInteger lambda_i = calculateLagrangeCoefficient(i, partials, delta);

            // Accumulate product: s_i ^ lambda_i mod n
            BigInteger term = partial.getSignatureShare().modPow(lambda_i, n);
            combinedSignature = combinedSignature.multiply(term).mod(n);
        }
        return combinedSignature;
    }

    private static BigInteger calculateLagrangeCoefficient(BigInteger i, List<PartialSignature> partials, BigInteger delta) {
        BigInteger numerator = delta;
        BigInteger denominator = BigInteger.ONE;

        for (PartialSignature other : partials) {
            if (other == null) continue;
            BigInteger j = BigInteger.valueOf(other.getServerId());
            if (i.equals(j)) continue;

            numerator = numerator.multiply(j);
            denominator = denominator.multiply(j.subtract(i));
        }
        return numerator.divide(denominator);
    }

    private static BigInteger factorial(int n) {
        BigInteger result = BigInteger.ONE;
        for (int i = 2; i <= n; i++) {
            result = result.multiply(BigInteger.valueOf(i));
        }
        return result;
    }

    public static boolean verifyThresholdSignature(BigInteger messageHash, BigInteger signature, BigInteger n, BigInteger e, int t) {
        BigInteger delta = factorial(t);
        BigInteger verificationValue = signature.modPow(e, n);
        BigInteger expectedValue = messageHash.modPow(delta, n);
        return verificationValue.equals(expectedValue);
    }

}