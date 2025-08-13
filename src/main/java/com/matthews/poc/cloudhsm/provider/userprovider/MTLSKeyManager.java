package com.matthews.poc.cloudhsm.provider.userprovider;

import lombok.SneakyThrows;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.FileReader;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class MTLSKeyManager extends X509ExtendedKeyManager {
    private final String privateKeyAlias;
    private final X509Certificate[] chain;
    private final PrivateKey key;

    public MTLSKeyManager(Provider provider, String privateKeyAlias) {
        this.key = loadKey(provider, privateKeyAlias);
        this.chain = loadCertChain(privateKeyAlias);
        this.privateKeyAlias = privateKeyAlias;
    }

    @SneakyThrows
    private PrivateKey loadKey(Provider provider, String alias) {
        try (PemReader reader = new PemReader(new FileReader(Path.of("certs", alias + ".key").toFile()))) {
            PemObject pemObject = reader.readPemObject();
            if (pemObject == null) {
                throw new RuntimeException("No PEM object found in key file: " + alias + ".key");
            }

            KeyFactory keyFactory = KeyFactory.getInstance("RSA", provider);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load CloudHSM key reference from file: " + alias + ".key - " + e.getMessage(), e);
        }
    }

    @SneakyThrows
    private X509Certificate[] loadCertChain(String alias) {
        try (PemReader reader = new PemReader(new FileReader(Path.of("certs", alias + ".pem").toFile()))) {
            List<X509Certificate> certificates = new ArrayList<>();
            PemObject pemObject;
            while ((pemObject = reader.readPemObject()) != null) {
                if ("CERTIFICATE".equals(pemObject.getType())) {
                    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(
                            new java.io.ByteArrayInputStream(pemObject.getContent())
                    );
                    certificates.add(cert);
                }
            }

            return certificates.toArray(new X509Certificate[0]);
        }
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[]{ privateKeyAlias };
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return privateKeyAlias;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType,
                                          Principal[] issuers, SSLEngine engine) {
        return privateKeyAlias;
    }

    @Override
    public String chooseEngineServerAlias(String keyType,
                                          Principal[] issuers, SSLEngine engine) {
        return privateKeyAlias;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[]{ privateKeyAlias };
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return privateKeyAlias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return chain;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return key;
    }
}
