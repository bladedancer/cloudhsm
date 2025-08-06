package com.matthews.poc.cloudhsm.provider.userprovider;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class KeystoreKeyManager extends X509ExtendedKeyManager {
    private final String privateKeyAlias;
    private final X509Certificate[] chain;
    private final PrivateKey key;

    public KeystoreKeyManager(KeyStore keyStore, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        this.privateKeyAlias = alias + ":Private";
        this.key = (PrivateKey) keyStore.getKey(privateKeyAlias, null);
        Certificate[] certs = keyStore.getCertificateChain(privateKeyAlias);
        if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate && !(certs instanceof X509Certificate[])) {
            Certificate[] tmp = new X509Certificate[certs.length];
            System.arraycopy(certs, 0, tmp, 0, certs.length);
            certs = tmp;
        }
        if (key == null || certs == null || certs.length == 0) {
            throw new KeyStoreException("No key/cert found in the keystore with label " + alias);
        }
        this.chain = (X509Certificate[]) certs;
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
