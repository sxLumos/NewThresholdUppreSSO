package server.idp;

import org.bouncycastle.math.ec.ECPoint;
import server.interfaces.TokenGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
//import storage.RedisStorage;
import utils.Pair;
import utils.SymmetricEncryptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap; // 引入 ConcurrentHashMap

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Base64;

public class IdentityProvider {
    private final int sid; // from 1 to numOfServer
    private final PublicKey publicKey;
    private final TokenGenerator tokenGenerator;
//    private BigInteger TOPRFKeyEnc;
//    private BigInteger TOPRFKeyUserID;
    // 新增：使用内存中的Map来替代Redis存储
    private final Map<String, UserInfo> userInfoStorage;
//    private final RedisStorage redisStorage;

    public record UserInfo(BigInteger keyShareEnc, BigInteger keyShareUserID, byte[] symmetricKey) {}

    public IdentityProvider(int sid, PublicKey publicKey,TokenGenerator tokenGenerator) {
        this.sid = sid;
        this.publicKey = publicKey;
        this.tokenGenerator = tokenGenerator;
        // 修改：初始化内存存储
        this.userInfoStorage = new ConcurrentHashMap<>();
//        this.redisStorage = RedisStorage.getInstance();
    }

    public int getSid() {
        return sid;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
//    public void setTOPRFKeyEnc(BigInteger encKeyShare) {
//        this.TOPRFKeyEnc = encKeyShare;
//    }
//    public void setTOPRFKeyUserID(BigInteger userIDKeyShare) {
//        this.TOPRFKeyUserID = userIDKeyShare;
//    }

    /**
     * 存储单个用户的记录到内存变量中。
     * @param record 用户信息对，格式为 <H(UserID||i), k_i>
     */
    public void storeUserInfo(Pair<String, UserInfo> record) {
        // 修改：将用户数据存储到内存Map中
        // 将 byte[] 类型的键转换为Base64字符串以确保作为Map键的可靠性
        String storageKey = record.getFirst();
        this.userInfoStorage.put(storageKey, record.getSecond());

        System.out.println("服务器 " + this.sid + " 已将用户数据存储到内存变量中。");
    }

    /**
     * 从内存变量中检索用户的对称密钥。
     * @param lookupKey 查找键 H(UserID||i)
     * @return 对应的对称密钥，如果未找到则返回 null
     */
    public byte[] retrieveSymmetricKey(String lookupKey) {
        if (lookupKey == null) {
            return null;
        }

        // 修改：从内存Map中检索用户数据
        // 同样将 lookupKey 转换为Base64字符串进行查找
        byte[] symmetricKey = this.userInfoStorage.get(lookupKey).symmetricKey;

        if (symmetricKey != null) {
            System.out.println("服务器 " + this.sid + " 从内存中查找到用户数据。");
        } else {
            System.out.println("服务器 " + this.sid + " 在内存中未找到对应记录。");
        }

        return symmetricKey;
    }

    /**
     * 从内存变量中检索用户的keyShareEnc。
     * @param lookupKey 查找键 H(UserID||i)
     * @return 对应的对称密钥，如果未找到则返回 null
     */
    public BigInteger retrieveKeyShareEnc(String lookupKey) {
        if (lookupKey == null) {
            return null;
        }
        // 修改：从内存Map中检索用户数据
        return this.userInfoStorage.get(lookupKey).keyShareEnc;
    }


    /**
     * 从内存变量中检索用户的keyShareID。
     * @param lookupKey 查找键 H(UserID||i)
     * @return 对应的对称密钥，如果未找到则返回 null
     */
    public BigInteger retrieveKeyShareID(String lookupKey) {
        if (lookupKey == null) {
            return null;
        }
        // 修改：从内存Map中检索用户数据
        return this.userInfoStorage.get(lookupKey).keyShareUserID;
    }

    /**
     * S1步骤: 计算 b_i = a^k_i
     * @param a 用户发送的盲化值
     * @return 部分 OPRF 结果 b_i
     */
    public ECPoint evaluateKeyEnc(BigInteger keyShareEnc,ECPoint a) {
        // 在椭圆曲线上，a^k_i 等价于 k_i * a
        return a.multiply(keyShareEnc).normalize();
    }

    /**
     * S1步骤: 计算 b_i = a^k_i
     * @param a 用户发送的盲化值
     * @return 部分 OPRF 结果 b_i
     */
    public ECPoint evaluateKeyUserID(BigInteger keyShareID, ECPoint a) {
        // 在椭圆曲线上，a^k_i 等价于 k_i * a
        return a.multiply(keyShareID).normalize();
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
    public void performUserRegister(Pair<String, UserInfo> serverStoreRecord) {
//        this.setTOPRFKeyEnc(keyShareEnc);
//        this.setTOPRFKeyUserID(keyShareUserID);
        this.storeUserInfo(serverStoreRecord);
    }

    /**
     * 仅由指定sid的服务器计算其本地token share
     */
    public Pair<Integer, Pair<String, ECPoint>> generateTokenShareFor(String userName, ECPoint blindInput, long startTimeSec, Map<String, Object> info) {
        //            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            digest.update(UserID);
//            digest.update(BigInteger.valueOf(this.getSid()).toByteArray());
//            digest.update(username.getBytes(StandardCharsets.UTF_8));
        byte[] symmetricKey = this.retrieveSymmetricKey(userName);
        BigInteger keyShareEnc = this.retrieveKeyShareEnc(userName);
        if (symmetricKey == null) {
            System.err.printf("❌ ERROR: Could not find symmetric key for IdP %d.%n", this.getSid());
            return null;
        }
        String plaintextTokenShare = this.generateTokenShare(startTimeSec, info);
        byte[] plaintextBytes = plaintextTokenShare.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedTokenBytes = SymmetricEncryptor.encrypt(plaintextBytes, symmetricKey);
        String encryptedTokenBase64 = Base64.getEncoder().encodeToString(encryptedTokenBytes);
        return Pair.of(this.getSid(), Pair.of(encryptedTokenBase64, this.evaluateKeyEnc(keyShareEnc, blindInput)));
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
