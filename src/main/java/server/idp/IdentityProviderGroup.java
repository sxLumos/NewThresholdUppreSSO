package server.idp;

import org.bouncycastle.math.ec.ECPoint;
import server.interfaces.KeyGenerator;
import server.interfaces.TokenGenerator;
import utils.CryptoUtil;
import utils.Pair;
import utils.SymmetricEncryptor;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class IdentityProviderGroup {
    private KeyGenerator keyGenerator;
    private List<IdentityProvider> idps;
    public int numOfServer;
    public int threshold;

    public void globalSetup(int numOfServer, int threshold) {
        // Generate private key shares for each server
        this.numOfServer = numOfServer;
        this.threshold = threshold;
        this.idps = new ArrayList<>(numOfServer);
        this.keyGenerator = new ThresholdRSAKeyGenerator(numOfServer, threshold, false);
        Map<String, Object> keySet = this.keyGenerator.getKeySet();
        // 从Map中获取密钥组件，并进行类型检查
        Object sharesObj = keySet.get(ThresholdRSAKeyGenerator.PRIVATE_KEY_SHARE);
        Object nObj = keySet.get(ThresholdRSAKeyGenerator.PUBLIC_KEY);

        if (!(sharesObj instanceof List<?>)) {
            throw new IllegalArgumentException("Key missing or has incorrect type for private_key_share");
        }
        if (!(nObj instanceof BigInteger)) {
            throw new IllegalArgumentException("Key missing or has incorrect type for modulus_n");
        }

        List<Pair<Integer, BigInteger>> allShares = (List<Pair<Integer, BigInteger>>) sharesObj;
        BigInteger n = (BigInteger) nObj;
        for (int i = 0; i < numOfServer; i++) {
            TokenGenerator tokenGenerator = new ThresholdRSAJWTTokenGenerator(n, allShares.get(i).getSecond(), allShares.get(i).getFirst());
            idps.add(new IdentityProvider(allShares.get(i).getFirst(), this.getPublicKey(),tokenGenerator)); // ServerID begin from 1
        }
    }

    public IdentityProvider getIdp(int sid) {
        if (sid < 1 || sid > this.numOfServer) return null;
        return this.idps.get(sid - 1);
    }

    public PublicKey getPublicKey() {
        return this.keyGenerator.getPublicKey();
    }

    public boolean verify(String content, byte[] signature, PublicKey publicKey) {
        return ThresholdRSAKeyGenerator.verify(content, signature, publicKey);
    }

    public static void main(String[] args) {
        IdentityProviderGroup idpGroup = new IdentityProviderGroup();
        idpGroup.globalSetup(10, 7);
    }
}
