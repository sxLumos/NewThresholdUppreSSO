package utils;

import org.bouncycastle.math.ec.ECPoint;

import java.nio.charset.StandardCharsets;

public class Rfc9380P256Utils {

    private static final byte[] DST = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
            .getBytes(StandardCharsets.US_ASCII);

    /**
     * 给定消息，生成 P-256 曲线上的安全点
     * 底层使用 Rfc9380P256.hash_to_curve
     *
     * @param msg 输入消息
     *
     * @return ECPoint 曲线点
     */
    public static ECPoint hashToCurve(byte[] msg) {
        // 返回 org.bouncycastle.math.ec.ECPoint 的椭圆曲线点
        return Rfc9380P256.hash_to_curve(msg, DST);
    }

    /**
     * 给定消息，生成 P-256 曲线标量
     * 底层使用 Rfc9380P256.hash_to_scalar
     *
     * @param msg 输入消息
     * @return BigInteger 标量
     */
    public static java.math.BigInteger hashToScalar(byte[] msg) {
        return Rfc9380P256.hash_to_scalar(msg, DST);
    }

    // 可选：直接传 String 版本
    public static ECPoint hashToCurve(String msg) {
        return hashToCurve(msg.getBytes(StandardCharsets.US_ASCII));
    }

    public static java.math.BigInteger hashToScalar(String msg) {
        return hashToScalar(msg.getBytes(StandardCharsets.US_ASCII));
    }
}
