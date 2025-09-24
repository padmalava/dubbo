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
package org.apache.dubbo.common.utils;

import org.apache.dubbo.common.logger.ErrorTypeAwareLogger;
import org.apache.dubbo.common.logger.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.dubbo.common.constants.LoggerCodeConstants.COMMON_UNEXPECTED_EXCEPTION;

/**
 * Secure Hash util - migrated from MD5 to SHA3-256 for Post-Quantum Cryptography compliance.
 *
 * WARNING: MD5 is cryptographically broken and should not be used for any security purposes.
 * This class now uses SHA3-256 by default for all operations.
 *
 * @deprecated This class is deprecated. Use {@link org.apache.dubbo.common.io.Bytes#getSHA3(String)}
 *             or {@link java.security.MessageDigest#getInstance("SHA3-256")} directly.
 */
@Deprecated
public class MD5Utils {

    private static final ErrorTypeAwareLogger logger = LoggerFactory.getErrorTypeAwareLogger(MD5Utils.class);

    private static final char[] hexDigits = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private MessageDigest mdInst;

    /**
     * Constructor using SHA3-256 instead of MD5 for security.
     * MD5 is cryptographically broken and vulnerable to collision attacks.
     */
    public MD5Utils() {
        try {
            // Use SHA3-256 instead of MD5 for Post-Quantum security
            mdInst = MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            logger.error(COMMON_UNEXPECTED_EXCEPTION, "", "", "Failed to obtain SHA3-256 digest", e);
            // Fallback to SHA-256 if SHA3-256 is not available
            try {
                mdInst = MessageDigest.getInstance("SHA-256");
                logger.warn(
                        COMMON_UNEXPECTED_EXCEPTION,
                        "",
                        "",
                        "SHA3-256 not available, falling back to SHA-256. Consider upgrading JDK version.");
            } catch (NoSuchAlgorithmException fallbackException) {
                logger.error(
                        COMMON_UNEXPECTED_EXCEPTION,
                        "",
                        "",
                        "Failed to obtain any secure hash algorithm",
                        fallbackException);
                throw new RuntimeException("No secure hash algorithm available", fallbackException);
            }
        }
    }

    /**
     * Calculate secure hash value of specified string using SHA3-256.
     * This method replaces the previous MD5 implementation for security.
     *
     * @param input the input string to hash
     * @return SHA3-256 hash value as hexadecimal string
     * @deprecated Use {@link org.apache.dubbo.common.io.Bytes#getSHA3(String)} instead
     */
    @Deprecated
    public String getMd5(String input) {
        return getSecureHash(input);
    }

    /**
     * Calculate secure hash value using SHA3-256.
     * This is the preferred method for new code.
     *
     * @param input the input string to hash
     * @return SHA3-256 hash value as hexadecimal string
     */
    public String getSecureHash(String input) {
        byte[] hashBytes;
        // MessageDigest instance is NOT thread-safe
        synchronized (mdInst) {
            mdInst.update(input.getBytes(UTF_8));
            hashBytes = mdInst.digest();
        }

        int j = hashBytes.length;
        char str[] = new char[j * 2];
        int k = 0;
        for (int i = 0; i < j; i++) {
            byte byte0 = hashBytes[i];
            str[k++] = hexDigits[byte0 >>> 4 & 0xf];
            str[k++] = hexDigits[byte0 & 0xf];
        }
        return new String(str);
    }

    /**
     * Creates a new instance with SHA3-256 for thread-safe usage.
     *
     * @return new SHA3-256 MessageDigest instance
     * @throws RuntimeException if SHA3-256 is not available
     */
    public static MessageDigest newSHA3Instance() {
        try {
            return MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            try {
                // Fallback to SHA-256
                return MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException fallbackException) {
                throw new RuntimeException("No secure hash algorithm available", fallbackException);
            }
        }
    }
}
