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

        BigInteger finalSignatureValue = combineSignatures(partialSignatures, n);
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
            boolean isValid = verifyThresholdSignature(messageHash, signature, n, e);

            if (!isValid) {
                throw new SignatureException("Threshold RSA signature verification failed.");
            }
            return JWT.decode(token);
        } catch (Exception e) {
            throw new SignatureException("Verification failed.", e);
        }
    }
    // CORRECTED: This method now handles negative exponents correctly.
    public static BigInteger combineSignatures(List<PartialSignature> partials, BigInteger n) {
        BigInteger combinedSignature = BigInteger.ONE;

        // Get the indices of the participating servers
        int[] serverIndices = partials.stream().mapToInt(PartialSignature::getServerId).toArray();

        for (PartialSignature partial : partials) {
            int i = partial.getServerId();

            // Calculate the standard Lagrange coefficient using pure integer arithmetic
            BigInteger lambda_i = calculateStandardLagrangeCoefficient(i, serverIndices);

            BigInteger base = partial.getSignatureShare();
            BigInteger exponent = lambda_i;

            // Handle negative exponents by using the modular inverse of the base
            if (exponent.signum() < 0) {
                base = base.modInverse(n);
                exponent = exponent.negate();
            }

            // Accumulate the product: s_i ^ lambda_i mod n
            BigInteger term = base.modPow(exponent, n);
            combinedSignature = combinedSignature.multiply(term).mod(n);
        }
        return combinedSignature;
    }

    // CORRECTED: This method now uses pure integer arithmetic, without the incorrect modulus.
    private static BigInteger calculateStandardLagrangeCoefficient(int i, int[] serverIndices) {
        BigInteger xi = BigInteger.valueOf(i);
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;

        for (int j : serverIndices) {
            if (i == j) {
                continue;
            }
            BigInteger xj = BigInteger.valueOf(j);
            // Numerator: product(xj)
            numerator = numerator.multiply(xj);
            // Denominator: product(xj - xi)
            denominator = denominator.multiply(xj.subtract(xi));
        }

        // The division must be exact for Lagrange coefficients
        return numerator.divide(denominator);
    }

    public static boolean verifyThresholdSignature(BigInteger messageHash, BigInteger signature, BigInteger n, BigInteger e) {
        // 标准验证: s^e == H(m)
        BigInteger verificationValue = signature.modPow(e, n);
        return verificationValue.equals(messageHash);
    }
}