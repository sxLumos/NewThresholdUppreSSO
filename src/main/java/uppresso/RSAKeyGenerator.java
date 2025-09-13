package uppresso;

import server.interfaces.KeyGenerator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * A standard RSA Key Generator that creates a single public/private key pair.
 * It can save the key to a file and load it back for persistence.
 * It also provides methods for signing data and verifying signatures.
 */
public class RSAKeyGenerator implements KeyGenerator {
    private BigInteger n; // RSA Modulus
    private BigInteger e; // RSA Public Exponent
    private BigInteger d; // RSA Private Exponent

    private static final int KEY_SIZE = 2048;
    // Renamed constants to be more generic
    public static final String PUBLIC_MODULUS = "n";
    public static final String PRIVATE_EXPONENT = "d";
    // Renamed filename for clarity
    private static final String KEY_FILENAME = "rsa_key.properties";

    /**
     * Constructor for the RSAKeyGenerator.
     * @param createNewKey If true, a new key pair will be generated.
     * If false, it will attempt to load an existing key from the file.
     */
    public RSAKeyGenerator(boolean createNewKey) {
        File keyFile = new File(KEY_FILENAME);
        // If createNew is true OR if we want to load but the file doesn't exist, generate a new key.
        if (createNewKey || !keyFile.exists()) {
            System.out.println("▶️ Generating new RSA key pair...");
            this.generateKey();
        } else {
            System.out.println("▶️ Loading existing RSA key pair from " + KEY_FILENAME + "...");
            this.loadKeyFromFile();
        }
    }

    /**
     * Generates a new RSA key pair and saves it to a file.
     */
    public void generateKey() {
        SecureRandom random = new SecureRandom();

        // 1. Generate RSA parameters (p, q, n, e, d, lambda)
        BigInteger p = new BigInteger(KEY_SIZE / 2, 100, random);
        BigInteger q = new BigInteger(KEY_SIZE / 2, 100, random);
        this.n = p.multiply(q);

        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        BigInteger lambda = pMinus1.multiply(qMinus1).divide(pMinus1.gcd(qMinus1));

        this.e = new BigInteger("65537");
        this.d = e.modInverse(lambda);

        // After generating, save the key to a file.
        saveKeyToFile();
    }

    /**
     * Saves the components of the RSA key pair (n, e, d) to a properties file.
     */
    public void saveKeyToFile() {
        Properties props = new Properties();
        props.setProperty("n", this.n.toString(16));
        props.setProperty("e", this.e.toString(16));
        props.setProperty("d", this.d.toString(16));

        try (FileOutputStream fos = new FileOutputStream(KEY_FILENAME)) {
            props.store(fos, "Standard RSA Key Data. DO NOT EDIT MANUALLY.");
            System.out.println("✅ Key successfully saved to " + KEY_FILENAME);
        } catch (IOException ex) {
            throw new RuntimeException("Failed to save key to file.", ex);
        }
    }

    /**
     * Loads the RSA key pair components from the properties file.
     */
    public void loadKeyFromFile() {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(KEY_FILENAME)) {
            props.load(fis);
        } catch (IOException ex) {
            throw new RuntimeException("Failed to load key from file: " + KEY_FILENAME, ex);
        }

        this.n = new BigInteger(props.getProperty("n"), 16);
        this.e = new BigInteger(props.getProperty("e"), 16);
        this.d = new BigInteger(props.getProperty("d"), 16);
        System.out.println("✅ Key successfully loaded.");
    }

    @Override
    public Map<String, Object> getKeySet() {
        if (this.n == null || this.d == null) {
            throw new IllegalStateException("Key has not been generated or loaded yet.");
        }
        Map<String, Object> keySet = new HashMap<>();
        // The keys in the map now reflect a single private key, not shares.
        keySet.put(PUBLIC_MODULUS, this.n);
        keySet.put(PRIVATE_EXPONENT, this.d);
        return keySet;
    }

    @Override
    public PublicKey getPublicKey() {
        if (this.n == null || this.e == null) {
            throw new IllegalStateException("Key has not been generated or loaded yet.");
        }
        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(this.n, this.e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to create public key object.", ex);
        }
    }

    // --- Sign and Verify methods are unchanged as they work on the master key pair ---

    @Override
    public byte[] sign(String content) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);
            PrivateKey rsaPrivateKey = keyFactory.generatePrivate(privateKeySpec);

            Signature rsaSign = Signature.getInstance("SHA256withRSA");
            rsaSign.initSign(rsaPrivateKey);
            rsaSign.update(content.getBytes(StandardCharsets.UTF_8));
            return rsaSign.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorithm not supported by current Java environment", e);
        }  catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid RSA private key", e);
        } catch (SignatureException | InvalidKeySpecException e) {
            throw new RuntimeException("Error occurred during signing process", e);
        }
    }

    public static boolean verify(String content, byte[] signature, PublicKey publicKey) {
        try {
            Signature rsaVerify = Signature.getInstance("SHA256withRSA");
            rsaVerify.initVerify(publicKey);
            rsaVerify.update(content.getBytes(StandardCharsets.UTF_8));
            return rsaVerify.verify(signature);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Algorithm not supported by current Java environment", ex);
        } catch (InvalidKeyException ex) {
            throw new RuntimeException("Invalid RSA public key", ex);
        } catch (SignatureException ex) {
            throw new RuntimeException("Error occurred during signature verification", ex);
        }
    }
}
