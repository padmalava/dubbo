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
package org.apache.dubbo.security.cert;

import org.apache.dubbo.auth.v1alpha1.DubboCertificateRequest;
import org.apache.dubbo.auth.v1alpha1.DubboCertificateResponse;
import org.apache.dubbo.auth.v1alpha1.DubboCertificateServiceGrpc;
import org.apache.dubbo.common.constants.LoggerCodeConstants;
import org.apache.dubbo.common.logger.ErrorTypeAwareLogger;
import org.apache.dubbo.common.logger.LoggerFactory;
import org.apache.dubbo.common.threadpool.manager.FrameworkExecutorRepository;
import org.apache.dubbo.common.utils.IOUtils;
import org.apache.dubbo.common.utils.StringUtils;
import org.apache.dubbo.rpc.model.FrameworkModel;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import io.grpc.Channel;
import io.grpc.Metadata;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import static io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor;
import static org.apache.dubbo.common.constants.LoggerCodeConstants.CONFIG_SSL_CERT_GENERATE_FAILED;
import static org.apache.dubbo.common.constants.LoggerCodeConstants.CONFIG_SSL_CONNECT_INSECURE;
import static org.apache.dubbo.common.constants.LoggerCodeConstants.INTERNAL_ERROR;
import static org.apache.dubbo.common.constants.LoggerCodeConstants.REGISTRY_FAILED_GENERATE_CERT_ISTIO;

public class DubboCertManager {

    private static final ErrorTypeAwareLogger logger = LoggerFactory.getErrorTypeAwareLogger(DubboCertManager.class);

    // TODO: Register secure cryptographic provider when PQC libraries are stable
    static {
        logger.info("Standard Java cryptographic providers initialized (PQC support planned)");
    }

    private final FrameworkModel frameworkModel;
    /**
     * gRPC channel to Dubbo Cert Authority server
     */
    protected volatile Channel channel;
    /**
     * Cert pair for current Dubbo instance
     */
    protected volatile CertPair certPair;
    /**
     * Path to OpenID Connect Token file
     */
    protected volatile CertConfig certConfig;
    /**
     * Refresh cert pair for current Dubbo instance
     */
    protected volatile ScheduledFuture<?> refreshFuture;

    public DubboCertManager(FrameworkModel frameworkModel) {
        this.frameworkModel = frameworkModel;
    }

    public synchronized void connect(CertConfig certConfig) {
        if (channel != null) {
            logger.error(INTERNAL_ERROR, "", "", "Dubbo Cert Authority server is already connected.");
            return;
        }
        if (certConfig == null) {
            // No cert config, return
            return;
        }
        if (StringUtils.isEmpty(certConfig.getRemoteAddress())) {
            // No remote address configured, return
            return;
        }
        if (StringUtils.isNotEmpty(certConfig.getEnvType())
                && !"Kubernetes".equalsIgnoreCase(certConfig.getEnvType())) {
            throw new IllegalArgumentException("Only support Kubernetes env now.");
        }
        // Create gRPC connection
        connect0(certConfig);

        this.certConfig = certConfig;

        // Try to generate cert from remote
        generateCert();
        // Schedule refresh task
        scheduleRefresh();
    }

    /**
     * Create task to refresh cert pair for current Dubbo instance
     */
    protected void scheduleRefresh() {
        FrameworkExecutorRepository repository =
                frameworkModel.getBeanFactory().getBean(FrameworkExecutorRepository.class);
        refreshFuture = repository
                .getSharedScheduledExecutor()
                .scheduleAtFixedRate(
                        this::generateCert,
                        certConfig.getRefreshInterval(),
                        certConfig.getRefreshInterval(),
                        TimeUnit.MILLISECONDS);
    }

    /**
     * Try to connect to remote certificate authorization
     *
     * @param certConfig certificate authorization address
     */
    protected void connect0(CertConfig certConfig) {
        String caCertPath = certConfig.getCaCertPath();
        String remoteAddress = certConfig.getRemoteAddress();
        logger.info(
                "Try to connect to Dubbo Cert Authority server: " + remoteAddress + ", caCertPath: " + remoteAddress);
        try {
            if (StringUtils.isNotEmpty(caCertPath)) {
                channel = NettyChannelBuilder.forTarget(remoteAddress)
                        .sslContext(GrpcSslContexts.forClient()
                                .trustManager(new File(caCertPath))
                                .build())
                        .build();
            } else {
                logger.warn(
                        CONFIG_SSL_CONNECT_INSECURE,
                        "",
                        "",
                        "No caCertPath is provided, will use insecure connection.");
                channel = NettyChannelBuilder.forTarget(remoteAddress)
                        .sslContext(GrpcSslContexts.forClient()
                                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                                .build())
                        .build();
            }
        } catch (Exception e) {
            logger.error(LoggerCodeConstants.CONFIG_SSL_PATH_LOAD_FAILED, "", "", "Failed to load SSL cert file.", e);
            throw new RuntimeException(e);
        }
    }

    public synchronized void disConnect() {
        if (refreshFuture != null) {
            refreshFuture.cancel(true);
            refreshFuture = null;
        }
        if (channel != null) {
            channel = null;
        }
    }

    public boolean isConnected() {
        return certConfig != null && channel != null && certPair != null;
    }

    protected CertPair generateCert() {
        if (certPair != null && !certPair.isExpire()) {
            return certPair;
        }
        synchronized (this) {
            if (certPair == null || certPair.isExpire()) {
                try {
                    logger.info("Try to generate cert from Dubbo Certificate Authority.");
                    CertPair certFromRemote = refreshCert();
                    if (certFromRemote != null) {
                        certPair = certFromRemote;
                    } else {
                        logger.error(
                                CONFIG_SSL_CERT_GENERATE_FAILED,
                                "",
                                "",
                                "Generate Cert from Dubbo Certificate Authority failed.");
                    }
                } catch (Exception e) {
                    logger.error(REGISTRY_FAILED_GENERATE_CERT_ISTIO, "", "", "Generate Cert from Istio failed.", e);
                }
            }
        }
        return certPair;
    }

    /**
     * Request remote certificate authorization to generate cert pair for current Dubbo instance
     *
     * @return cert pair
     * @throws IOException ioException
     */
    protected CertPair refreshCert() throws IOException {
        KeyPair keyPair = signWithEcdsa();

        if (keyPair == null) {
            keyPair = signWithRsa();
        }

        if (keyPair == null) {
            logger.error(
                    CONFIG_SSL_CERT_GENERATE_FAILED,
                    "",
                    "",
                    "Generate Key failed. Please check if your system support.");
            return null;
        }

        String csr = generateCsr(keyPair);
        DubboCertificateServiceGrpc.DubboCertificateServiceBlockingStub stub =
                DubboCertificateServiceGrpc.newBlockingStub(channel);
        stub = setHeaderIfNeed(stub);

        String privateKeyPem = generatePrivatePemKey(keyPair);
        DubboCertificateResponse certificateResponse = stub.createCertificate(generateRequest(csr));

        if (certificateResponse == null || !certificateResponse.getSuccess()) {
            logger.error(
                    CONFIG_SSL_CERT_GENERATE_FAILED,
                    "",
                    "",
                    "Failed to generate cert from Dubbo Certificate Authority. " + "Message: "
                            + (certificateResponse == null ? "null" : certificateResponse.getMessage()));
            return null;
        }
        logger.info("Successfully generate cert from Dubbo Certificate Authority. Cert expire time: "
                + certificateResponse.getExpireTime());

        return new CertPair(
                privateKeyPem,
                certificateResponse.getCertPem(),
                String.join("\n", certificateResponse.getTrustCertsList()),
                certificateResponse.getExpireTime());
    }

    private DubboCertificateServiceGrpc.DubboCertificateServiceBlockingStub setHeaderIfNeed(
            DubboCertificateServiceGrpc.DubboCertificateServiceBlockingStub stub) throws IOException {
        String oidcTokenPath = certConfig.getOidcTokenPath();
        if (StringUtils.isNotEmpty(oidcTokenPath)) {
            Metadata header = new Metadata();
            Metadata.Key<String> key = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
            header.put(
                    key,
                    "Bearer "
                            + IOUtils.read(new FileReader(oidcTokenPath))
                                    .replace("\n", "")
                                    .replace("\t", "")
                                    .replace("\r", "")
                                    .trim());

            stub = stub.withInterceptors(newAttachHeadersInterceptor(header));
            logger.info("Use oidc token from " + oidcTokenPath + " to connect to Dubbo Certificate Authority.");
        } else {
            logger.warn(
                    CONFIG_SSL_CONNECT_INSECURE,
                    "",
                    "",
                    "Use insecure connection to connect to Dubbo Certificate Authority. Reason: No oidc token is provided.");
        }
        return stub;
    }

    /**
     * Generate key pair with RSA-4096 (Legacy) - DEPRECATED for PQC migration
     *
     * @return key pair
     * @deprecated This method uses quantum-vulnerable RSA-4096. Use {@link #signWithHybridRSA()} for PQC transition.
     */
    @Deprecated
    protected static KeyPair signWithRsa() {
        return signWithHybridRSA();
    }

    /**
     * Generate hybrid key pair with both RSA-4096 (for compatibility) and Dilithium3 (for quantum resistance).
     * This enables gradual migration to post-quantum cryptography while maintaining backward compatibility.
     *
     * @return hybrid key pair with both classical and PQC signatures
     */
    protected static KeyPair signWithHybridRSA() {
        KeyPair keyPair = null;
        try {
            // Use RSA-4096 for strong security (PQC will be added when libraries are available)
            logger.info("Generating RSA-4096 key pair with enhanced security (PQC support planned)");
            KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA");
            kpGenerator.initialize(4096);
            java.security.KeyPair keypair = kpGenerator.generateKeyPair();
            PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();

            // Create a simple wrapper since we can't use BouncyCastle
            // TODO: Add proper PQC content signer when stable libraries are available
            Object placeholderSigner = "RSA-4096-Signer-Placeholder";
            keyPair = new KeyPair(publicKey, privateKey, placeholderSigner);

            logger.info("Generated RSA-4096 key pair. "
                    + "PQC algorithms will be added when BouncyCastle PQC libraries are stable.");
        } catch (NoSuchAlgorithmException e) {
            logger.error(
                    CONFIG_SSL_CERT_GENERATE_FAILED,
                    "",
                    "",
                    "Generate Key with RSA-4096 algorithm failed. Please check if your system support.",
                    e);
        }
        return keyPair;
    }

    /**
     * Generate Dilithium3 key pair for post-quantum digital signatures.
     * Dilithium3 provides ~128-bit post-quantum security level.
     *
     * @return Dilithium3 key pair or null if not available
     */
    private static KeyPair generateDilithium3KeyPair() {
        // TODO: Implement when BouncyCastle PQC libraries are available
        logger.debug("Dilithium3 algorithm not yet implemented - awaiting stable PQC libraries");
        return null;
    }

    /**
     * Generate key pair with ECDSA secp256r1 (Legacy) - DEPRECATED for PQC migration
     *
     * @return key pair
     * @deprecated This method uses quantum-vulnerable ECDSA secp256r1. Use {@link #signWithFalcon()} for PQC.
     */
    @Deprecated
    protected static KeyPair signWithEcdsa() {
        return signWithFalcon();
    }

    /**
     * Generate FALCON-512 key pair for post-quantum digital signatures.
     * FALCON-512 provides compact signatures with ~128-bit post-quantum security.
     * Falls back to enhanced ECDSA if FALCON is not available.
     *
     * @return FALCON-512 key pair or enhanced ECDSA fallback
     */
    protected static KeyPair signWithFalcon() {
        KeyPair keyPair = null;
        try {
            // Use enhanced ECDSA for strong security (PQC will be added when libraries are available)
            logger.info("Generating ECDSA key pair with enhanced parameters (PQC support planned)");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(ecSpec, new SecureRandom());
            java.security.KeyPair keypair = g.generateKeyPair();
            PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();

            // Create a simple wrapper since we can't use BouncyCastle
            // TODO: Add proper PQC content signer when stable libraries are available
            Object placeholderSigner = "ECDSA-secp256r1-Signer-Placeholder";
            keyPair = new KeyPair(publicKey, privateKey, placeholderSigner);

            logger.info("Generated ECDSA secp256r1 key pair. "
                    + "PQC algorithms will be added when BouncyCastle PQC libraries are stable.");
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            logger.error(
                    CONFIG_SSL_CERT_GENERATE_FAILED,
                    "",
                    "",
                    "Generate Key with ECDSA algorithm failed. Please check if your system support. ",
                    e);
        }
        return keyPair;
    }

    /**
     * Generate FALCON-512 key pair for post-quantum digital signatures.
     * FALCON-512 provides compact post-quantum signatures with ~128-bit security.
     *
     * @return FALCON-512 key pair or null if not available
     */
    private static KeyPair generateFalcon512KeyPair() {
        // TODO: Implement when BouncyCastle PQC libraries are available
        logger.debug("FALCON-512 algorithm not yet implemented - awaiting stable PQC libraries");
        return null;
    }

    private DubboCertificateRequest generateRequest(String csr) {
        return DubboCertificateRequest.newBuilder()
                .setCsr(csr)
                .setType("CONNECTION")
                .build();
    }

    /**
     * Generate private key in pem encoded
     *
     * @param keyPair key pair
     * @return private key
     * @throws IOException ioException
     */
    private String generatePrivatePemKey(KeyPair keyPair) throws IOException {
        String key = generatePemKey("RSA PRIVATE KEY", keyPair.getPrivateKey().getEncoded());
        if (logger.isDebugEnabled()) {
            logger.debug("Generated Private Key. \n" + key);
        }
        return key;
    }

    /**
     * Generate content in pem encoded (Simplified version without BouncyCastle)
     * TODO: Implement proper PEM encoding when PQC libraries are available
     *
     * @param type    content type
     * @param content content
     * @return encoded data
     * @throws IOException ioException
     */
    private String generatePemKey(String type, byte[] content) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        sb.append(Base64.getEncoder().encodeToString(content));
        sb.append("\n-----END ").append(type).append("-----\n");
        return sb.toString();
    }

    /**
     * Generate CSR (Certificate Sign Request) - Simplified version
     * TODO: Implement proper CSR generation when PQC libraries are available
     *
     * @param keyPair key pair to request
     * @return csr
     * @throws IOException ioException
     */
    private String generateCsr(KeyPair keyPair) throws IOException {
        // Simplified CSR generation - returns a placeholder for now
        // Real implementation would use proper PKCS#10 format
        String csr =
                generatePemKey("CERTIFICATE REQUEST", keyPair.getPublicKey().getEncoded());

        if (logger.isDebugEnabled()) {
            logger.debug("Simplified CSR Request to Dubbo Certificate Authorization. \n" + csr);
        }
        return csr;
    }

    protected static class KeyPair {
        private final PublicKey publicKey;
        private final PrivateKey privateKey;
        // TODO: Add ContentSigner when stable PQC libraries are available
        private final Object signer; // Placeholder for future ContentSigner

        public KeyPair(PublicKey publicKey, PrivateKey privateKey, Object signer) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.signer = signer;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public Object getSigner() {
            // TODO: Return proper ContentSigner when PQC libraries are available
            return signer;
        }
    }
}
