package utils;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;


public final class Rfc9380P256 {

    // suite 常量
    private static final String SUITE_ID = "HashToCurve-RO-P256-SHA256-SSWU-";
    private static final byte[] SUITE_ID_BYTES = SUITE_ID.getBytes();
    private static final int Fp_BYTES = 32;                  // 256-bit
    private static final BigInteger P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    private static final BigInteger B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger Z = P.subtract(BigInteger.valueOf(10));

    private static final ECParameterSpec PARAMS = ECNamedCurveTable.getParameterSpec("secp256r1");

    public static class HashToCurveResult {
        public final BigInteger u0;
        public final BigInteger u1;
        public final ECPoint Q0;
        public final ECPoint Q1;
        public final ECPoint P;

        public HashToCurveResult(BigInteger u0, BigInteger u1, ECPoint Q0, ECPoint Q1, ECPoint P) {
            this.u0 = u0;
            this.u1 = u1;
            this.Q0 = Q0;
            this.Q1 = Q1;
            this.P = P;
        }
    }

    public static HashToCurveResult hash_to_curve_debug(byte[] msg, byte[] dst) {
        byte[] dstPrime = Arrays.copyOf(dst, dst.length + 1);
        dstPrime[dst.length] = (byte) dst.length;

        int L_BYTES = 48;
        int count = 2;
        byte[] uniform = expand_message_xmd(msg, dstPrime, count * L_BYTES);

        BigInteger u0 = new BigInteger(1, Arrays.copyOfRange(uniform, 0, L_BYTES)).mod(P);
        BigInteger u1 = new BigInteger(1, Arrays.copyOfRange(uniform, L_BYTES, 2 * L_BYTES)).mod(P);

        ECPoint Q0 = map_to_curve_simple_swu(u0);
        ECPoint Q1 = map_to_curve_simple_swu(u1);
        ECPoint Ppoint = Q0.add(Q1).normalize();   // cofactor=1

        return new HashToCurveResult(u0, u1, Q0, Q1, Ppoint);
    }


    // expand_message_xmd
    public static byte[] expand_message_xmd(byte[] msg, byte[] dstPrime, int len) {
        try {
            if (dstPrime.length > 255 || len > 65535) throw new IllegalArgumentException("dst/len too long");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            int ell = (len + 31) / 32;

            byte[] lenBytes = shortToBytes(len, 2);
            byte[] Zpad = new byte[64];

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(Zpad);
            baos.write(msg);
            baos.write(lenBytes);
            baos.write((byte) 0);
            baos.write(dstPrime);
            byte[] msgPrime = baos.toByteArray();

            // Compute b_0 = H(msgPrime)
            md.update(msgPrime);
            byte[] b0 = md.digest();

            /* 2. b_1 = H(b_0 || 0x01 || DST_prime) */
            md.reset();
            md.update(b0);
            md.update((byte) 1);
            md.update(dstPrime);
            byte[] b1 = md.digest();

            byte[] out = Arrays.copyOf(b1, len);
            for (int i = 2; i <= ell; i++) {
                md.reset();
                byte[] tmp = new byte[32];
                for (int j = 0; j < 32; j++) tmp[j] = (byte) (b0[j] ^ b1[j]);
                md.update(tmp);
                md.update((byte) i);
                md.update(dstPrime);
                b1 = md.digest();
                int copyLen = Math.min(32, len - (i - 1) * 32);
                System.arraycopy(b1, 0, out, (i - 1) * 32, copyLen);
            }
            return out;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /* 大端 I2OSP */
    private static byte[] shortToBytes(int v, int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) (v >> (8 * (len - 1 - i)));
        return b;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] c = new byte[a.length];
        for (int i = 0; i < a.length; i++) c[i] = (byte) (a[i] ^ b[i]);
        return c;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // simple_swu
    public static ECPoint map_to_curve_simple_swu(BigInteger u) {
        org.bouncycastle.math.ec.ECCurve curve = PARAMS.getCurve();
        BigInteger P = curve.getField().getCharacteristic();

        ECFieldElement A = curve.getA();
        ECFieldElement B = curve.getB();

        /* 1. 预计算常量 */
        ECFieldElement zFe   = curve.fromBigInteger(Z);               // Z = -2 mod P
        ECFieldElement c1 = B.divide(A);                          // c1 = B / A
        ECFieldElement c2 = zFe.multiply(zFe).invert();               // c2 = 1 / Z²

        /* 2. 计算 tv1 = 1 / (Z²·u⁴ + Z·u²)   [如果分母=0则按异常处理] */
        ECFieldElement uFe = curve.fromBigInteger(u.mod(P));
        ECFieldElement u2  = uFe.square();
        ECFieldElement Zu2 = zFe.multiply(u2);
        ECFieldElement den = Zu2.multiply(zFe.multiply(u2).add(curve.fromBigInteger(BigInteger.ONE))); // Z²u⁴ + Zu²
        if (den.isZero()) {          // 异常分支 u=0 或 Z²u⁴+Zu²=0
            ECFieldElement x1 = c1.divide(zFe);        // x1 = B/(Z·A)
            ECFieldElement gx1 = x1.square().add(A).multiply(x1).add(B);
            ECFieldElement y1 = gx1.sqrt();
            if (y1 == null) throw new IllegalStateException("exceptional case QR fail");
            BigInteger yBig = y1.toBigInteger().mod(P);
            if (yBig.testBit(0)) yBig = P.subtract(yBig);
            return curve.createPoint(x1.toBigInteger().mod(P), yBig).normalize();
        }
        ECFieldElement tv1 = den.invert();

        /* 3. x1 = (-B/A) * (1 + tv1) */
        ECFieldElement x1 = c1.negate().multiply(tv1.add(curve.fromBigInteger(BigInteger.ONE)));

        /* 4. x2 = Z * u² * x1 */
        ECFieldElement x2 = Zu2.multiply(x1);

        /* 5. 选分支 */
        ECFieldElement gx1 = x1.square().add(A).multiply(x1).add(B);
        ECFieldElement y1 = gx1.sqrt();
        final ECFieldElement x, y;
        if (y1 != null) {
            x = x1;
            y = y1;
        } else {
            ECFieldElement gx2 = x2.square().add(A).multiply(x2).add(B);
            ECFieldElement y2 = gx2.sqrt();
            if (y2 == null) throw new IllegalStateException("2nd candidate QR fail");
            x = x2;
            y = y2;
        }

        /* 6. 调整 y 符号 */
        BigInteger yBig = y.toBigInteger().mod(P);
        if (u.testBit(0) != yBig.testBit(0)) {   // sgn0(u) != sgn0(y)
            yBig = P.subtract(yBig);
        }
        return curve.createPoint(x.toBigInteger().mod(P), yBig).normalize();
    }


    public static ECPoint hash_to_curve(byte[] msg, byte[] dst) {
        byte[] dstPrime = Arrays.copyOf(dst, dst.length + 1);
        dstPrime[dst.length] = (byte) dst.length;

        // RFC: for P-256, L = 48, count=2 => len = 96
        int L_BYTES = 48;
        int count = 2;
        byte[] uniform = expand_message_xmd(msg, dstPrime, count * L_BYTES); // 96 bytes

        BigInteger u0 = new BigInteger(1, Arrays.copyOfRange(uniform, 0, L_BYTES)).mod(P);
        BigInteger u1 = new BigInteger(1, Arrays.copyOfRange(uniform, L_BYTES, 2 * L_BYTES)).mod(P);

        ECPoint q0 = map_to_curve_simple_swu(u0);
        ECPoint q1 = map_to_curve_simple_swu(u1);
        return q0.add(q1).normalize();   // cofactor=1
    }

    public static BigInteger hash_to_scalar(byte[] msg, byte[] dst) {
        byte[] dstPrime = Arrays.copyOf(dst, dst.length + 1);
        dstPrime[dst.length] = (byte) dst.length;
        byte[] buf = expand_message_xmd(msg, dstPrime, 48);
        return new BigInteger(1, buf).mod(PARAMS.getN());
    }

    public static void main(String[] args) {
        byte[] msg = "abcdef0123456789".getBytes(StandardCharsets.US_ASCII);
        byte[] dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
                .getBytes(StandardCharsets.US_ASCII);

        // 调用 debug 版本
        HashToCurveResult result = hash_to_curve_debug(msg, dst);

        int L_BYTES = 48;  // u0/u1 长度
        int COORD_BYTES = 32; // 曲线坐标长度

        System.out.println("u0 = " + toFixedLengthHex(result.u0, COORD_BYTES));
        System.out.println("want  0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c");
        System.out.println("u1 = " + toFixedLengthHex(result.u1, COORD_BYTES));
        System.out.println("want  b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb");

        System.out.println("Q0.x = " + toFixedLengthHex(result.Q0.getAffineXCoord().toBigInteger(), COORD_BYTES));
        System.out.println("want  a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2");
        System.out.println("Q0.y = " + toFixedLengthHex(result.Q0.getAffineYCoord().toBigInteger(), COORD_BYTES));
        System.out.println("want  4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e");

        System.out.println("Q1.x = " + toFixedLengthHex(result.Q1.getAffineXCoord().toBigInteger(), COORD_BYTES));
        System.out.println("want  7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66");
        System.out.println("Q1.y = " + toFixedLengthHex(result.Q1.getAffineYCoord().toBigInteger(), COORD_BYTES));
        System.out.println("want  b765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9");

        System.out.println("P.x = " + toFixedLengthHex(result.P.getAffineXCoord().toBigInteger(), COORD_BYTES));
        System.out.println("want  65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80");
        System.out.println("P.y = " + toFixedLengthHex(result.P.getAffineYCoord().toBigInteger(), COORD_BYTES));
        System.out.println("want  cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3");
    }

    private static String toFixedLengthHex(BigInteger n, int byteLen) {
        String hex = n.toString(16); // 转为十六进制字符串，不带前导 0
        int expectedLen = byteLen * 2; // 每个字节对应 2 个字符
        if (hex.length() < expectedLen) {
            // 补前导零
            StringBuilder sb = new StringBuilder(expectedLen);
            for (int i = 0; i < expectedLen - hex.length(); i++) {
                sb.append('0');
            }
            sb.append(hex);
            return sb.toString();
        } else if (hex.length() > expectedLen) {
            // 如果意外超长，取低位
            return hex.substring(hex.length() - expectedLen);
        } else {
            return hex;
        }
    }





}
