package verifier.interfaces;

import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.PublicKey;

/**
 * An interface for verifying JSON Web Tokens.
 * Implementations will contain the logic specific to a given signature algorithm.
 */
public interface JWTVerifier {

    /**
     * Verifies a given JWT string against a public key.
     *
     * @param token     The complete JWT string to verify.
     * @param publicKey The public key corresponding to the private key used for signing.
     * @return A DecodedJWT object if the signature is valid, allowing access to claims.
     * @throws Exception if the token is malformed or the signature is invalid.
     */
    static DecodedJWT verify(String token, PublicKey publicKey) throws Exception {
        return null;
    }
}