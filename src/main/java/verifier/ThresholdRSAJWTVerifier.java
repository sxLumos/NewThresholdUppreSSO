package verifier;


import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import config.SystemConfig;
import org.bouncycastle.math.ec.ECPoint;
import utils.CryptoUtil;
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
    public static BigInteger combineSignatures(List<PartialSignature> partials, BigInteger n) {
        BigInteger delta = CryptoUtil.factorial(SystemConfig.NUM_SERVERS);
        BigInteger combinedSignature = BigInteger.ONE;
        int[] serverIndices = partials.stream().mapToInt(PartialSignature::getServerId).toArray();

        for (PartialSignature partial : partials) {
            int i = partial.getServerId();

            // Calculate the integer Lagrange coefficient L_i = Δ * λ_i
            BigInteger lambda_i = calculateIntegerLagrangeCoefficient(i, serverIndices, delta);

            BigInteger base = partial.getSignatureShare();
            BigInteger exponent = lambda_i;

            if (exponent.signum() < 0) {
                base = base.modInverse(n);
                exponent = exponent.negate();
            }

            BigInteger term = base.modPow(exponent, n);
            combinedSignature = combinedSignature.multiply(term).mod(n);
        }
        return combinedSignature;
    }

    /**
     * Calculate the integer Lagrange coefficient Lᵢ = Δ * ∏(j≠i) (-j)/(i-j)
     */
    private static BigInteger calculateIntegerLagrangeCoefficient(int i, int[] serverIndices, BigInteger delta) {
        BigInteger xi = BigInteger.valueOf(i);
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;

        for (int j : serverIndices) {
            if (i == j) {
                continue;
            }
            BigInteger xj = BigInteger.valueOf(j);
            // Numerator: product of (-j)
            numerator = numerator.multiply(xj.negate());
            // Denominator: product of (i - j)
            denominator = denominator.multiply(xi.subtract(xj));
        }

        // Calculate L_i = delta * numerator / denominator. This is guaranteed to be an integer.
        return delta.multiply(numerator).divide(denominator);
    }

//    public static boolean verifyThresholdSignature(BigInteger messageHash, BigInteger signature, BigInteger n, BigInteger e) {
//        // 标准验证: s^e == H(m)
//        BigInteger verificationValue = signature.modPow(e, n);
//        return verificationValue.equals(messageHash);
//    }

    /**
     * 使用修正后的协议验证门限签名。
     * 此方法会执行两次模幂运算来验证 s^e ≡ (H(m))^(Δ^2) (mod n)。
     *
     * @param messageHash 原始消息的哈希值 H(m)
     * @param signature   待验证的最终聚合签名 s
     * @param n           RSA 公共模数 n
     * @param e           RSA 公共指数 e
     * @param delta       修正因子 Δ (等于服务器总数的阶乘)
     * @return 如果签名有效则返回 true，否则返回 false
     */
    public static boolean verifyThresholdSignature(BigInteger messageHash, BigInteger signature, BigInteger n, BigInteger e) {
        BigInteger delta = CryptoUtil.factorial(SystemConfig.NUM_SERVERS);
        // 第一次模幂：计算等式左边 s^e mod n
        BigInteger signatureVerification = signature.modPow(e, n);

        // 准备计算等式右边
        BigInteger deltaSquared = delta.multiply(delta);

        // 第二次模幂：计算等式右边 (H(m))^(Δ^2) mod n
        BigInteger targetVerification = messageHash.modPow(deltaSquared, n);

        // 比较两边的结果
        return signatureVerification.equals(targetVerification);
    }
}