package utils;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class CryptoUtil {

    public static final String CURVE_NAME = "secp256r1"; // 也被称为 P-256
    public static final ECParameterSpec EC_SPEC;
    public static final BigInteger ORDER; // 循环群的阶 n (不是 m)
    public static final ECPoint GENERATOR; // 循环群的生成元 G
    private static final BigInteger FIELD_PRIME; // 曲线所在有限域的素数 p
    private static final BigInteger CURVE_A;
    private static final BigInteger CURVE_B;
    private static final BigInteger CURVE_P;


    static {
        Security.addProvider(new BouncyCastleProvider());
        EC_SPEC = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        ORDER = EC_SPEC.getN();
        GENERATOR = EC_SPEC.getG();
        // 获取曲线方程 y^2 = x^3 + ax + b 的参数
        FIELD_PRIME = EC_SPEC.getCurve().getField().getCharacteristic();
        CURVE_A = EC_SPEC.getCurve().getA().toBigInteger();
        CURVE_B = EC_SPEC.getCurve().getB().toBigInteger();
        CURVE_P = EC_SPEC.getCurve().getField().getCharacteristic();
    }

    public static ECPoint hashToPoint(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input);
            BigInteger k = new BigInteger(1, hash);
            return GENERATOR.multiply(k).normalize();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing algorithm not found", e);
        }
    }

    /**
     * [安全实现] H1: 将任意字节数组通过 "Hash-and-Try" 方法安全地哈希到椭圆曲线上。
     * 此方法符合现代密码学协议对哈希到曲线函数的要求，输出点的离散对数是未知的。
     * @param input 任意长度的输入数据
     * @return 曲线上的一个有效点
     */
    public static ECPoint hashToCurve(byte[] input) {
        return Rfc9380P256Utils.hashToCurve(input);
//        try {
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            // 使用一个 domain separation tag 来确保哈希用途的唯一性
//            byte[] domainSeparator = "HashToCurve_".getBytes();
//
//            // 使用 "Hash-and-Try" 方法
//            for (int counter = 0; counter < 256; counter++) {
//                // 1. 哈希(输入 || 计数器) 来获得候选的 x 坐标
//                ByteBuffer buffer = ByteBuffer.allocate(domainSeparator.length + input.length + 1);
//                buffer.put(domainSeparator);
//                buffer.put(input);
//                buffer.put((byte) counter);
//                byte[] hash = digest.digest(buffer.array());
//
//                BigInteger xCand = new BigInteger(1, hash);
//
//                // 确保 x 在有限域 F_p 内
//                xCand = xCand.mod(FIELD_PRIME);
//
//                // 2. 使用曲线方程 y^2 = x^3 + ax + b (mod p) 计算 y^2
//                BigInteger ySquared = xCand.pow(3).add(CURVE_A.multiply(xCand)).add(CURVE_B).mod(FIELD_PRIME);
//
//                // 3. 检查 y^2 是否是模 p 的二次剩余，即计算其模平方根
//                // BouncyCastle 的 ECFieldElement.sqrt() 是完成此任务的完美工具
//                ECFieldElement ySquaredField = EC_SPEC.getCurve().fromBigInteger(ySquared);
//                ECFieldElement yField = ySquaredField.sqrt();
//
//                if (yField != null) {
//                    // 4. 如果找到了平方根，我们成功了
//                    BigInteger y = yField.toBigInteger();
//                    // 5. 创建并返回点
//                    return EC_SPEC.getCurve().createPoint(xCand, y).normalize();
//                }
//                // 6. 如果没有找到，循环将继续，尝试下一个计数器值
//            }
//
//            // 如果尝试了256次仍然失败（对于SHA-256几乎不可能），则抛出异常
//            throw new RuntimeException("Failed to hash to curve point after 256 attempts.");
//
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException("SHA-256 algorithm not found", e);
//        }
    }


    // =================================================================
    //  您已有的其他函数保持不变
    // =================================================================

    /**
     * H2: 将椭圆曲线上的点哈希为一个固定长度的字节数组
     * @param point 曲线上的点
     * @return 哈希值 H2(point)
     */
    public static byte[] hashPointToBytes(ECPoint point) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedPoint = point.getEncoded(true); // 使用压缩表示
            return digest.digest(encodedPoint);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing algorithm not found", e);
        }
    }

    public static BigInteger randomScalar() {
        SecureRandom random = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(ORDER.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) == 0 || r.compareTo(ORDER) >= 0);
        return r;
    }

    public static byte[] calculateExpectedOutput(byte[] x, BigInteger masterKey) {
        // 重要：这里应该使用安全的 hashToCurve
        ECPoint h1x = CryptoUtil.hashToPoint(x);
        ECPoint prfResultPoint = h1x.multiply(masterKey).normalize();
        return CryptoUtil.hashPointToBytes(prfResultPoint);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static ECPoint decodePointFromHex(String hexEncodedPoint) {
        byte[] encodedBytes = hexToBytes(hexEncodedPoint);
        return EC_SPEC.getCurve().decodePoint(encodedBytes);
    }

    public static BigInteger hashToScalar(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return new BigInteger(1, hash).mod(CryptoUtil.ORDER);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not found", e);
        }
    }

    /**
     * 用于演示和测试的主函数
     */
    public static void main(String[] args) {
        byte[] input = "163.com".getBytes();

        System.out.println("曲线: " + CURVE_NAME);
        System.out.println("有限域素数 (p): " + FIELD_PRIME.toString(16));
        System.out.println("阶 (n): " + ORDER.toString(16));
        System.out.println("----------------------------------------------------");

        // 使用不安全的方法
        ECPoint insecurePoint = hashToPoint(input);
        System.out.println("不安全方法 (insecureHashToPoint):");
        System.out.println("  输出点: " + bytesToHex(insecurePoint.getEncoded(false)));
        // 我们可以轻易验证其与G的关系
        BigInteger k = new BigInteger(1, Digest.sha256(input));
        ECPoint calculatedPoint = GENERATOR.multiply(k).normalize();
        System.out.println("  验证 (k*G): " + bytesToHex(calculatedPoint.getEncoded(false)));
        System.out.println("  点是否相等: " + insecurePoint.equals(calculatedPoint));
        System.out.println("----------------------------------------------------");


        // 使用安全的方法
        ECPoint securePoint = hashToCurve(input);
        System.out.println("安全方法 (hashToCurve):");
        System.out.println("  输出点: " + bytesToHex(securePoint.getEncoded(false)));
        // 我们无法知道其离散对数 k'，使得 securePoint = k' * G
        System.out.println("  此点的离散对数是未知的，符合安全要求。");
        System.out.println("----------------------------------------------------");

        // 验证确定性：相同的输入总是产生相同的输出
        ECPoint securePoint2 = hashToCurve(input);
        System.out.println("确定性验证:");
        System.out.println("  第二次哈希: " + bytesToHex(securePoint2.getEncoded(false)));
        System.out.println("  两次结果是否相等: " + securePoint.equals(securePoint2));

        System.out.println(isPointOnCurve(securePoint));
    }
    /**
     * 验证点是否在曲线上
     */
    private static boolean isPointOnCurve(ECPoint point) {
        if (point.isInfinity()) {
            return true;
        }

        BigInteger x = point.getXCoord().toBigInteger();
        BigInteger y = point.getYCoord().toBigInteger();

        // 检查 y^2 = x^3 + ax + b
        BigInteger left = y.multiply(y).mod(CURVE_P);
        BigInteger right = x.pow(3).add(CURVE_A.multiply(x)).add(CURVE_B).mod(CURVE_P);

        return left.equals(right);
    }

    // 辅助类，用于main函数中的sha256调用
    static class Digest {
        public static byte[] sha256(byte[] data) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(data);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }
}