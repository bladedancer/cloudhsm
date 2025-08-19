package com.matthews.poc.cloudhsm.provider.userprovider;

import lombok.SneakyThrows;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.FileReader;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class KeystoreKeyManager extends X509ExtendedKeyManager {
    private String alias;
    private X509Certificate[] chain;
    private PrivateKey key;


    public KeystoreKeyManager(KeyStore keyStore, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        String privateKeyLabel = alias + ":Private";
        key = (PrivateKey) keyStore.getKey(privateKeyLabel, null);
        if (key != null) {
            this.alias = privateKeyLabel;
            chain = loadCertChain(alias);
        }

        if (key == null) {
            key = (PrivateKey) keyStore.getKey(alias, null);
            if (key != null) {
                this.alias = alias;
                chain = loadCertChain(alias);
            }
        }

        if (key == null) {
            // List available aliases for debugging
            java.util.Enumeration<String> aliases = keyStore.aliases();
            StringBuilder availableAliases = new StringBuilder();
            while (aliases.hasMoreElements()) {
                availableAliases.append(aliases.nextElement()).append(", ");
            }
            throw new RuntimeException("Private key not found in CloudHSM. Tried: " + privateKeyLabel + " and " + alias +
                    ". Available aliases: " + availableAliases.toString());
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
        return new String[]{ alias };
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType,
                                          Principal[] issuers, SSLEngine engine) {
        return alias;
    }

    @Override
    public String chooseEngineServerAlias(String keyType,
                                          Principal[] issuers, SSLEngine engine) {
        return alias;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[]{ alias };
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return alias;
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
