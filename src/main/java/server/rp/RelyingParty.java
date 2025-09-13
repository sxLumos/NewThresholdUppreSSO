package server.rp;

import org.bouncycastle.math.ec.ECPoint;
import server.idp.Certificate;
import storage.RedisStorage;
import utils.CryptoUtil;

import java.util.Map;

public class RelyingParty {
    private ECPoint identity; // ID_RP
    private Certificate certificate; // Cert_RP
    private static final String RP_ID = "default_rp";
    private final RedisStorage redisStorage;
    private String rpHost;

    public static void main(String[] args) {
        RelyingParty p = new RelyingParty();
    }
    public RelyingParty() {
        this.redisStorage = RedisStorage.getInstance();
        
        // 只从Redis加载
//        if (!loadStateFromRedis()) {
//            System.out.println("Redis中没有找到RP证书数据，需要重新注册");
//        }
    }

    public Certificate getCertificate() {
        return this.certificate;
    }

    public void setRpHost(String rpHost) {
        this.rpHost = rpHost;
    }

    /**
     * 设置RP的身份与证书（供RP服务器在通过网络完成注册后注入）
     */
    public void setIdentityAndCert(ECPoint identity, byte[] signature) {
        this.identity = identity;
        this.certificate = new Certificate(this.rpHost, identity, signature);
    }

    
    /**
     * 将RP状态保存到Redis
     */
    public void saveStateToRedis() {
        if (this.identity == null || this.certificate == null) {
            System.err.println("错误：RP尚未注册，无法保存状态到Redis。");
            return;
        }
        
        String identityHex = CryptoUtil.bytesToHex(this.identity.getEncoded(true));
        String signatureHex = CryptoUtil.bytesToHex(this.certificate.getSignature());

        redisStorage.storeRPCertificate(RP_ID, identityHex, signatureHex);
        // 同步扩展状态（含公钥）依旧走 storeRPState
        System.out.println("RP的状态已成功保存到Redis");
    }
    
    /**
     * 从Redis加载RP状态
     */
    public boolean loadStateFromRedis() {
        try {
            Map<String, String> certData = redisStorage.retrieveRPCertificate(RP_ID);
            if (certData == null || certData.isEmpty()) {
                System.out.println("Redis中没有找到RP证书数据");
                return false;
            }
            
            String identityHex = certData.get("identity");
            String signatureHex = certData.get("signature");
            
            if (identityHex == null || signatureHex == null) {
                System.err.println("Redis中的RP证书数据不完整");
                return false;
            }
            
            // 解码并设置身份
            this.identity = CryptoUtil.decodePointFromHex(identityHex);
            
            // 重建证书（rpHost 从扩展状态取）
            Map<String, String> rpState = redisStorage.retrieveRPState(RP_ID);
            if (rpState != null) this.rpHost = rpState.get("rpHost");
            byte[] signature = CryptoUtil.hexToBytes(signatureHex);
            this.certificate = new Certificate(this.rpHost, this.identity, signature);
            
            System.out.println("RP的状态已从Redis成功加载");
            System.out.println("  - 加载的身份 (ID_RP): " + this.identity);
            return true;
        } catch (Exception e) {
            System.err.println("从Redis加载RP状态失败: " + e.getMessage());
            return false;
        }
    }
}
