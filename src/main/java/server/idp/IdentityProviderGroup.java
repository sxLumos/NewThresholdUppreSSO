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
    public List<Pair<Integer, Pair<String, ECPoint>>> generateTokenShares(byte[] UserID, ECPoint blindInput, long startTimeSec, Map<String, Object> info) {
        List<Pair<Integer, Pair<String, ECPoint>>> tokenShares = new ArrayList<>();
        for(int i = 0;i < this.numOfServer;i ++ ){
            try {
                IdentityProvider idp = this.idps.get(i);
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(UserID);
                digest.update(BigInteger.valueOf(idp.getSid()).toByteArray());
                byte[] symmetricKey = idp.retrieveSymmetricKey(digest.digest());
                if (symmetricKey == null) {
                    System.err.printf("❌ ERROR: Could not find symmetric key for IdP %d. Skipping token share generation.%n", idp.getSid());
                    continue;
                }
                // --- Step 2: Generate the plaintext token share (the JWT string) ---
                String plaintextTokenShare = idp.generateTokenShare(startTimeSec, info);
                byte[] plaintextBytes = plaintextTokenShare.getBytes(StandardCharsets.UTF_8);

                // --- Step 3: Encrypt the token share using the symmetric key ---
                byte[] encryptedTokenBytes = SymmetricEncryptor.encrypt(plaintextBytes, symmetricKey);

                // --- Step 4: Encode the encrypted bytes to a Base64 string for easy transport ---
                String encryptedTokenBase64 = Base64.getEncoder().encodeToString(encryptedTokenBytes);

//                System.out.printf("   - IdP %d: Plaintext token generated, then encrypted and Base64 encoded.%n", idp.getSid());

                // --- Step 5: Add the encrypted share to the list ---
                tokenShares.add(Pair.of(idp.getSid(), Pair.of(encryptedTokenBase64, idp.evaluateKeyEnc(blindInput))));
//                tokenShares.add(Pair.of(idp.getSid(), idp.generateTokenShare(startTimeSec, info)));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return tokenShares;
    }

    /**
     * 仅由指定sid的服务器计算其本地token share
     */
    public Pair<Integer, Pair<String, ECPoint>> generateTokenShareFor(int sid, byte[] UserID, ECPoint blindInput, long startTimeSec, Map<String, Object> info) {
        try {
            if (sid < 1 || sid > this.numOfServer) return null;
            IdentityProvider idp = this.idps.get(sid - 1);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(UserID);
            digest.update(BigInteger.valueOf(idp.getSid()).toByteArray());
            byte[] symmetricKey = idp.retrieveSymmetricKey(digest.digest());
            if (symmetricKey == null) {
                System.err.printf("❌ ERROR: Could not find symmetric key for IdP %d.%n", idp.getSid());
                return null;
            }
            String plaintextTokenShare = idp.generateTokenShare(startTimeSec, info);
            byte[] plaintextBytes = plaintextTokenShare.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedTokenBytes = SymmetricEncryptor.encrypt(plaintextBytes, symmetricKey);
            String encryptedTokenBase64 = Base64.getEncoder().encodeToString(encryptedTokenBytes);
            return Pair.of(idp.getSid(), Pair.of(encryptedTokenBase64, idp.evaluateKeyEnc(blindInput)));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    public Pair<ECPoint, Certificate> performRPRegister() {
        // 保留旧接口但不再使用随机ID，实际新流程由服务器处理
        BigInteger r = CryptoUtil.randomScalar();
        ECPoint idRp = CryptoUtil.GENERATOR.multiply(r).normalize();
        String content = CryptoUtil.bytesToHex(idRp.getEncoded(true));
        byte[] signature = this.keyGenerator.sign(content);
        Certificate certRp = new Certificate(idRp, signature);
        return Pair.of(idRp, certRp);
    }

    public void performUserRegister(List<Pair<Integer, BigInteger>> keyShareEnc, List<Pair<Integer, BigInteger>> keyShareUserID, List<Pair<byte[], byte[]>> serverStoreRecord) {
        for(int i = 0;i < this.numOfServer;i ++ ) {
            IdentityProvider idp = this.idps.get(i);
            idp.setTOPRFKeyEnc(keyShareEnc.get(i).getSecond());
            idp.setTOPRFKeyUserID(keyShareUserID.get(i).getSecond());
            idp.storeUserInfo(serverStoreRecord.get(i));
        }
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
