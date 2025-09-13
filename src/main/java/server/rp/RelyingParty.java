package server.rp;

import org.bouncycastle.math.ec.ECPoint;
import server.idp.Certificate;


public class RelyingParty {
    private ECPoint identity; // ID_RP
    private Certificate certificate; // Cert_RP
    private static final String RP_ID = "default_rp";
    private String rpHost;

    public static void main(String[] args) {
        RelyingParty p = new RelyingParty();
    }
    public RelyingParty() {

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

}
