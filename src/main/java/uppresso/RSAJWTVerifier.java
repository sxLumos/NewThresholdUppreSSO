package uppresso;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import verifier.interfaces.JWTVerifier;

import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * A standard RSA JWT Verifier.
 * It uses the com.auth0.java-jwt library to verify a complete JWT signed with SHA256withRSA.
 */
public class RSAJWTVerifier implements JWTVerifier {

    /**
     * Verifies a standard RS256 JWT using the provided public key.
     * All logic for combining shares and custom threshold verification has been removed.
     *
     * @param token The complete JWT string to verify (e.g., "header.payload.signature").
     * @param publicKey The standard RSA public key to use for verification.
     * @return A DecodedJWT object if the signature is valid and all claims are correct.
     * @throws JWTVerificationException if the token is invalid (bad signature, expired, etc.).
     */
    public static DecodedJWT verify(String token, PublicKey publicKey) throws JWTVerificationException {
        // 1. Ensure the provided key is an RSA Public Key.
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of RSAPublicKey.");
        }

        try {
            // 2. Create an Algorithm instance using the public key.
            //    The private key is not needed for verification, so it can be null.
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, (RSAPrivateKey) null);

            // 3. Build the verifier using the algorithm.
            //    You can add more verification rules here, like .withIssuer("MyIssuer").
            com.auth0.jwt.JWTVerifier verifier = JWT.require(algorithm).build();

            // 4. Perform the verification. The library handles everything:
            //    - Decoding the signature
            //    - Hashing the header and payload
            //    - Verifying the signature against the hash and public key
            return verifier.verify(token);

        } catch (JWTVerificationException e){
            // The library's exception is re-thrown. It provides detailed information
            // about why the verification failed (e.g., SignatureVerificationException, TokenExpiredException).
            System.err.println("JWT Verification Failed: " + e.getMessage());
            throw e;
        }
    }
}
