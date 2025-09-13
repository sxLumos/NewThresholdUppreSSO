package server.interfaces;

import java.util.Map;

/**
 * Generic interface for producing access tokens or credentials.
 *
 */
public interface TokenGenerator {

    /**
     * Generates a partial signature for a given message hash.
     * @return A string encoding of the token or credential.
     * @throws Exception If something goes wrong.
     */
    String generateToken(long startTimeSec, Map<String, Object> info) throws Exception;

}

