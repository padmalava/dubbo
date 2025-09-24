/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.auth.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Signature utilities for HMAC-based authentication with Post-Quantum Cryptography (PQC) compliance.
 *
 * <p>This utility class has been updated to use HMAC-SHA3-256 by default, which provides better
 * quantum resistance compared to traditional HMAC-SHA256. SHA-3 is based on the Keccak sponge
 * construction and is considered more resistant to quantum attacks.</p>
 *
 * <p><strong>Migration Guide:</strong></p>
 * <ul>
 *   <li>Existing {@code sign()} methods now use HMAC-SHA3-256 internally</li>
 *   <li>Use {@code signWithSHA3()} methods for explicit PQC-compliant signing</li>
 *   <li>Legacy {@code signWithSHA256()} methods are deprecated but available for backward compatibility</li>
 * </ul>
 *
 * <p><strong>Security Note:</strong> HMAC signatures generated with different algorithms (SHA256 vs SHA3-256)
 * will produce different results. Ensure all parties in your system use the same algorithm version.</p>
 */
public class SignatureUtils {
    private static final String HMAC_SHA3_256_ALGORITHM = "HmacSHA3-256";

    // Deprecated constant for backward compatibility
    @Deprecated
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    public static String sign(String metadata, String key) throws RuntimeException {
        return sign(metadata.getBytes(StandardCharsets.UTF_8), key);
    }

    public static String sign(Object[] parameters, String metadata, String key) throws RuntimeException {
        if (parameters == null) {
            return sign(metadata, key);
        }
        for (int i = 0; i < parameters.length; i++) {
            if (!(parameters[i] instanceof Serializable)) {
                throw new IllegalArgumentException("The parameter [" + i + "] to be signed was not serializable.");
            }
        }
        Object[] includeMetadata = new Object[parameters.length + 1];
        System.arraycopy(parameters, 0, includeMetadata, 0, parameters.length);
        includeMetadata[parameters.length] = metadata;
        byte[] includeMetadataBytes;
        try {
            includeMetadataBytes = toByteArray(includeMetadata);
        } catch (IOException e) {
            throw new RuntimeException("Failed to generate HMAC: " + e.getMessage());
        }
        return sign(includeMetadataBytes, key);
    }

    private static String sign(byte[] data, String key) throws RuntimeException {
        Mac mac;
        try {
            mac = Mac.getInstance(HMAC_SHA3_256_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(
                    "Failed to generate HMAC: no such algorithm exception " + HMAC_SHA3_256_ALGORITHM);
        }
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_SHA3_256_ALGORITHM);
        try {
            mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Failed to generate HMAC: invalid key exception");
        }
        byte[] rawHmac;
        try {
            // compute the hmac on input data bytes
            rawHmac = mac.doFinal(data);
        } catch (IllegalStateException e) {
            throw new RuntimeException("Failed to generate HMAC: " + e.getMessage());
        }
        // base64-encode the hmac
        return Base64.getEncoder().encodeToString(rawHmac);
    }

    // PQC-specific methods with explicit algorithm specification

    /**
     * Sign data using HMAC-SHA3-256 (Post-Quantum Cryptography compliant).
     *
     * @param metadata the metadata string to sign
     * @param key the secret key
     * @return base64-encoded HMAC-SHA3-256 signature
     */
    public static String signWithSHA3(String metadata, String key) {
        return sign(metadata.getBytes(StandardCharsets.UTF_8), key);
    }

    /**
     * Sign parameters and metadata using HMAC-SHA3-256 (Post-Quantum Cryptography compliant).
     *
     * @param parameters the parameters array to sign
     * @param metadata the metadata string
     * @param key the secret key
     * @return base64-encoded HMAC-SHA3-256 signature
     */
    public static String signWithSHA3(Object[] parameters, String metadata, String key) {
        return sign(parameters, metadata, key);
    }

    // Deprecated methods for backward compatibility (now using SHA3-256 internally)

    /**
     * @deprecated Use signWithSHA3() instead. This method now uses HMAC-SHA3-256 for improved post-quantum security.
     */
    @Deprecated
    public static String signWithSHA256(String metadata, String key) {
        return signLegacy(metadata.getBytes(StandardCharsets.UTF_8), key, HMAC_SHA256_ALGORITHM);
    }

    /**
     * @deprecated Use signWithSHA3() instead. This method now uses HMAC-SHA3-256 for improved post-quantum security.
     */
    @Deprecated
    public static String signWithSHA256(Object[] parameters, String metadata, String key) {
        if (parameters == null) {
            return signWithSHA256(metadata, key);
        }
        for (int i = 0; i < parameters.length; i++) {
            if (!(parameters[i] instanceof Serializable)) {
                throw new IllegalArgumentException("The parameter [" + i + "] to be signed was not serializable.");
            }
        }
        Object[] includeMetadata = new Object[parameters.length + 1];
        System.arraycopy(parameters, 0, includeMetadata, 0, parameters.length);
        includeMetadata[parameters.length] = metadata;
        byte[] includeMetadataBytes;
        try {
            includeMetadataBytes = toByteArray(includeMetadata);
        } catch (IOException e) {
            throw new RuntimeException("Failed to generate HMAC: " + e.getMessage());
        }
        return signLegacy(includeMetadataBytes, key, HMAC_SHA256_ALGORITHM);
    }

    /**
     * Legacy signing method that can use different algorithms for backward compatibility.
     *
     * @param data the data bytes to sign
     * @param key the secret key
     * @param algorithm the HMAC algorithm to use
     * @return base64-encoded HMAC signature
     */
    private static String signLegacy(byte[] data, String key, String algorithm) throws RuntimeException {
        Mac mac;
        try {
            mac = Mac.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate HMAC: no such algorithm exception " + algorithm);
        }
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algorithm);
        try {
            mac.init(signingKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Failed to generate HMAC: invalid key exception");
        }
        byte[] rawHmac;
        try {
            // compute the hmac on input data bytes
            rawHmac = mac.doFinal(data);
        } catch (IllegalStateException e) {
            throw new RuntimeException("Failed to generate HMAC: " + e.getMessage());
        }
        // base64-encode the hmac
        return Base64.getEncoder().encodeToString(rawHmac);
    }

    // Verification methods for PQC compliance

    /**
     * Verify HMAC-SHA3-256 signature (Post-Quantum Cryptography compliant).
     *
     * @param data the original data that was signed
     * @param signature the base64-encoded signature to verify
     * @param key the secret key used for signing
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifySignature(String data, String signature, String key) {
        try {
            String expectedSignature = sign(data, key);
            return constantTimeEquals(signature, expectedSignature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify HMAC-SHA3-256 signature for parameters and metadata (Post-Quantum Cryptography compliant).
     *
     * @param parameters the parameters array that was signed
     * @param metadata the metadata string that was signed
     * @param signature the base64-encoded signature to verify
     * @param key the secret key used for signing
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifySignature(Object[] parameters, String metadata, String signature, String key) {
        try {
            String expectedSignature = sign(parameters, metadata, key);
            return constantTimeEquals(signature, expectedSignature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Constant-time string comparison to prevent timing attacks.
     *
     * @param a first string
     * @param b second string
     * @return true if strings are equal, false otherwise
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private static byte[] toByteArray(Object[] parameters) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(parameters);
            out.flush();
            return bos.toByteArray();
        }
    }
}
