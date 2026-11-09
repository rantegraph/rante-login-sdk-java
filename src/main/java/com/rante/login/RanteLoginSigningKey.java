package com.rante.login;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * A Signed JWT key linked to the app: its prefix as the Rante Portal shows it (sent as the client assertion's
 * {@code kid}) and its private key, RSA of at least 2048 bits (RS256) or EC P-256 (ES256).
 */
public final class RanteLoginSigningKey {
    private static final Pattern KEY_PREFIX = Pattern.compile("^rk_live_[0-9a-f]{24}$");

    private final String keyPrefix;
    private final PrivateKey privateKey;
    private final JWSAlgorithm algorithm;

    private RanteLoginSigningKey(String keyPrefix, PrivateKey privateKey, JWSAlgorithm algorithm) {
        this.keyPrefix = keyPrefix;
        this.privateKey = privateKey;
        this.algorithm = algorithm;
    }

    /** From an unencrypted PKCS#8 PEM private key ({@code -----BEGIN PRIVATE KEY-----}, as openssl genpkey writes). */
    public static RanteLoginSigningKey fromPem(String keyPrefix, String pem) {
        checkPrefix(keyPrefix);
        if (pem == null || !pem.contains("-----BEGIN PRIVATE KEY-----")) {
            throw invalid("The signing key must be an unencrypted PKCS#8 PEM private key (-----BEGIN PRIVATE KEY-----).");
        }
        byte[] der;
        try {
            der = Base64.getMimeDecoder().decode(pem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").trim());
        } catch (IllegalArgumentException error) {
            throw invalid("The signing key's PEM could not be decoded.");
        }
        for (String type : new String[] {"RSA", "EC"}) {
            try {
                return fromPrivateKey(keyPrefix, KeyFactory.getInstance(type).generatePrivate(new PKCS8EncodedKeySpec(der)));
            } catch (java.security.GeneralSecurityException ignored) {
                // Not this key type: try the next.
            }
        }
        throw invalid("The signing key must be an RSA or EC P-256 private key.");
    }

    /** From an RSA private key of at least 2048 bits (RS256) or an EC P-256 private key (ES256). */
    public static RanteLoginSigningKey fromPrivateKey(String keyPrefix, PrivateKey privateKey) {
        checkPrefix(keyPrefix);
        if (privateKey instanceof RSAPrivateKey rsa) {
            if (rsa.getModulus().bitLength() < 2048) {
                throw invalid("RSA signing keys must have at least 2048 bits.");
            }
            return new RanteLoginSigningKey(keyPrefix, privateKey, JWSAlgorithm.RS256);
        }
        if (privateKey instanceof ECPrivateKey ec) {
            if (!Curve.P_256.equals(Curve.forECParameterSpec(ec.getParams()))) {
                throw invalid("EC signing keys must use the P-256 curve (ES256).");
            }
            return new RanteLoginSigningKey(keyPrefix, privateKey, JWSAlgorithm.ES256);
        }
        throw invalid("The signing key must be an RSA or EC P-256 private key.");
    }

    /** The key's prefix (rk_live_ and 24 hex digits). */
    public String keyPrefix() {
        return keyPrefix;
    }

    /** {@code RS256} or {@code ES256}. */
    public String algorithm() {
        return algorithm.getName();
    }

    PrivateKey privateKey() {
        return privateKey;
    }

    JWSAlgorithm jwsAlgorithm() {
        return algorithm;
    }

    private static void checkPrefix(String keyPrefix) {
        if (keyPrefix == null || !KEY_PREFIX.matcher(keyPrefix).matches()) {
            throw invalid("The key prefix must be the one the Rante Portal shows: rk_live_ and 24 hex digits.");
        }
    }

    private static RanteLoginException invalid(String message) {
        return new RanteLoginException("invalid_configuration", message);
    }
}
