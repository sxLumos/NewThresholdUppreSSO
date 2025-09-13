package server.idp;

import org.bouncycastle.math.ec.ECPoint;
import utils.CryptoUtil;

/**
 * Represents the certificate issued by the IdP to an RP.
 */
public class Certificate {
    private final ECPoint ID_RP;
    private final byte[] signature;
    private final String rpHost;

    public Certificate(ECPoint idRp, byte[] signature) {
        this.ID_RP = idRp;
        this.signature = signature;
        this.rpHost = null;
    }

    public Certificate(String rpHost, ECPoint idRp, byte[] signature) {
        this.rpHost = rpHost;
        this.ID_RP = idRp;
        this.signature = signature;
    }
    public String getEncodeContent() {
        return CryptoUtil.bytesToHex(this.ID_RP.getEncoded(true));
    }
    // Getters for all fields
    public ECPoint getID_RP() { return ID_RP; }
    public byte[] getSignature() { return signature; }
    public String getRpHost() { return rpHost; }

    @Override
    public String toString() {
        return String.format("[RP_HOST=%s, ID_RP=%s, Signature=%s]",
                rpHost,
                ID_RP.toString(),
                CryptoUtil.bytesToHex(signature).substring(0, 16) + "...");
    }
}