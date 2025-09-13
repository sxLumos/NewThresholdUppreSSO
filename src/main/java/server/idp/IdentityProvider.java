package server.idp;

import org.bouncycastle.math.ec.ECPoint;
import server.interfaces.TokenGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import storage.RedisStorage;
import utils.Pair;
import utils.SymmetricEncryptor;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

public class IdentityProvider {
    private final int sid; // from 1 to numOfServer
    private final PublicKey publicKey;
    private final TokenGenerator tokenGenerator;
    private BigInteger TOPRFKeyEnc;
    private BigInteger TOPRFKeyUserID;
    private final RedisStorage redisStorage;

    public IdentityProvider(int sid, PublicKey publicKey,TokenGenerator tokenGenerator) {
        this.sid = sid;
        this.publicKey = publicKey;
        this.tokenGenerator = tokenGenerator;
        this.redisStorage = RedisStorage.getInstance();
    }

    public int getSid() {
        return sid;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public void setTOPRFKeyEnc(BigInteger encKeyShare) {
        this.TOPRFKeyEnc = encKeyShare;
    }
    public void setTOPRFKeyUserID(BigInteger userIDKeyShare) {
        this.TOPRFKeyUserID = userIDKeyShare;
    }


    /**
     * 存储单个用户的记录到Redis。
     * @param userInfo 用户信息对，格式为 <H(UserID||i), k_i>
     */
    public void storeUserInfo(Pair<byte[], byte[]> userInfo) {
        if (userInfo == null || userInfo.getFirst() == null || userInfo.getSecond() == null) {
            System.err.println("错误：服务器 " + this.sid + " 收到空的或无效的用户信息。");
            return;
        }

        byte[] lookupKey = userInfo.getFirst();   // This is H(UserID||i)
        byte[] symmetricKey = userInfo.getSecond(); // This is k_i

        // 使用Redis存储用户数据
        redisStorage.storeUserData(this.sid, lookupKey, symmetricKey);
        System.out.println("服务器 " + this.sid + " 已将用户数据存储到Redis。");
    }

    /**
     * 从Redis检索用户的对称密钥。
     * @param lookupKey 查找键 H(UserID||i)
     * @return 对应的对称密钥，如果未找到则返回 null
     */
    public byte[] retrieveSymmetricKey(byte[] lookupKey) {
        if (lookupKey == null) {
            return null;
        }
        
        // 从Redis检索用户数据
        byte[] symmetricKey = redisStorage.retrieveUserData(this.sid, lookupKey);
        
        if (symmetricKey != null) {
            System.out.println("服务器 " + this.sid + " 从Redis查找到用户数据。");
        } else {
            System.out.println("服务器 " + this.sid + " 在Redis中未找到对应记录。");
        }
        
        return symmetricKey;
    }

    /**
     * S1步骤: 计算 b_i = a^k_i
     * @param a 用户发送的盲化值
     * @return 部分 OPRF 结果 b_i
     */
    public ECPoint evaluateKeyEnc(ECPoint a) {
        // 在椭圆曲线上，a^k_i 等价于 k_i * a
        return a.multiply(this.TOPRFKeyEnc).normalize();
    }

    /**
     * S1步骤: 计算 b_i = a^k_i
     * @param a 用户发送的盲化值
     * @return 部分 OPRF 结果 b_i
     */
    public ECPoint evaluateKeyUserID(ECPoint a) {
        // 在椭圆曲线上，a^k_i 等价于 k_i * a
        return a.multiply(this.TOPRFKeyUserID).normalize();
    }

    public String generateTokenShare(long startTimeSec, Map<String, Object> info) {
        try {
            return this.tokenGenerator.generateToken(startTimeSec, info);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public void performUserRegister(BigInteger keyShareEnc, BigInteger keyShareUserID, Pair<byte[], byte[]> serverStoreRecord) {
        this.setTOPRFKeyEnc(keyShareEnc);
        this.setTOPRFKeyUserID(keyShareUserID);
        this.storeUserInfo(serverStoreRecord);
    }

    /**
     * 仅由指定sid的服务器计算其本地token share
     */
    public Pair<Integer, Pair<String, ECPoint>> generateTokenShareFor(byte[] UserID, ECPoint blindInput, long startTimeSec, Map<String, Object> info) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(UserID);
            digest.update(BigInteger.valueOf(this.getSid()).toByteArray());
            byte[] symmetricKey = this.retrieveSymmetricKey(digest.digest());
            if (symmetricKey == null) {
                System.err.printf("❌ ERROR: Could not find symmetric key for IdP %d.%n", this.getSid());
                return null;
            }
            String plaintextTokenShare = this.generateTokenShare(startTimeSec, info);
            byte[] plaintextBytes = plaintextTokenShare.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedTokenBytes = SymmetricEncryptor.encrypt(plaintextBytes, symmetricKey);
            String encryptedTokenBase64 = Base64.getEncoder().encodeToString(encryptedTokenBytes);
            return Pair.of(this.getSid(), Pair.of(encryptedTokenBase64, this.evaluateKeyEnc(blindInput)));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }


    /**
     * 生成对任意内容的阈值RSA签名份额 s_i = H(m)^{d_i} mod n
     */
    public BigInteger generateSignatureShare(byte[] contentBytes) {
        if (this.tokenGenerator instanceof ThresholdRSAJWTTokenGenerator gen) {
            try {
                return gen.generateSignatureShare(contentBytes);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
        throw new IllegalStateException("Unsupported token generator type for signature share generation");
    }
}
