package verifier;

import java.math.BigInteger;

public class PartialSignature {
    private final int serverId;
    private final BigInteger signatureShare;

    public PartialSignature(int serverId, BigInteger signatureShare) {
        this.serverId = serverId;
        this.signatureShare = signatureShare;
    }

    public int getServerId() {
        return serverId;
    }

    public BigInteger getSignatureShare() {
        return signatureShare;
    }
}