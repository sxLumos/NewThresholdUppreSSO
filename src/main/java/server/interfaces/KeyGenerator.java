package server.interfaces;

import java.security.PublicKey;
import java.util.Map;

public interface KeyGenerator {
    Map<String, Object> getKeySet() ;
    PublicKey getPublicKey();
    byte[] sign(String content);
//    boolean verify(String content, byte[] signature, PublicKey publicKey);
}
