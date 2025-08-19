package com.matthews.poc.cloudhsm.provider.userprovider;

import com.matthews.poc.cloudhsm.api.ProviderService;
import com.matthews.poc.cloudhsm.api.Session;
import io.quarkus.runtime.Startup;
import io.quarkus.runtime.util.StringUtil;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.crypto.Mac;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.security.auth.callback.Callback;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AuthProvider;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
@Named("UserProviderService")
@Startup
@Slf4j
public class UserProviderService implements ProviderService {
    private final Map<String, AuthProvider> userProviders = new ConcurrentHashMap<>();

    @ConfigProperty(name = "cloudhsm.clusterid")
    String clusterId;

    @ConfigProperty(name = "cloudhsm.cafile")
    String cafile;

    @ConfigProperty(name = "cloudhsm.ip")
    String ip;

    @ConfigProperty(name = "cloudhsm.port")
    Integer port;

    @ConfigProperty(name = "cloudhsm.user")
    String defaultUser;

    @ConfigProperty(name = "cloudhsm.password")
    String defaultPassword;

    @PostConstruct
    public void init() {
        log.info("ProviderService initialized.");
    }

    @PreDestroy
    public void cleanup() {
        log.info("Cleaning up user-specific providers...");
        userProviders.values().forEach(provider -> {
            try {
                provider.logout();
            } catch (Exception e) {
                log.error("Error during provider logout: {}", e.getMessage(), e);
            }
        });
        userProviders.clear();
    }

    public Session login(String user, String password) throws Exception {
        UserSession session = new UserSession(StringUtil.isNullOrEmpty(user) ? defaultUser : user, clusterId);
        if (userProviders.containsKey(session.key())) {
            log.info("User {} is already logged in.", session.user());
            return session;
        }

        // Keying the provider by user name just as example.....
        String pkcs11Config = String.format("""
            --
            name=CloudHSM_%s
            library=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so
            """, session.user());
        AuthProvider provider = (AuthProvider) Security.getProvider("SunPKCS11").configure(pkcs11Config);

        provider.login(null, callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof javax.security.auth.callback.PasswordCallback passwordCallback) {
                    passwordCallback.setPassword(
                            String.format("%s:%s",
                                    session.user(),
                                    StringUtil.isNullOrEmpty(password) ? defaultPassword : password).toCharArray());
                    break;
                }
            }
        });

        Security.addProvider(provider);

        userProviders.put(session.key(), provider);
        log.info("User {} logged in successfully.", user);
        return session;
    }

    public void logout(Session session) {
        UserSession userSession = (UserSession) session;

        AuthProvider provider = userProviders.remove(userSession.key());
        if (provider != null) {
            try {
                provider.logout();
                Security.removeProvider(provider.getName());
                log.info("User {} logged out successfully.", userSession.user());
            } catch (Exception e) {
                log.error("Error during logout for user {}: {}", userSession.user(), e.getMessage(), e);
            }
        } else {
            log.warn("No provider found for user {}.", userSession.user());
        }
    }

    @Override
    public SSLContext getSSLContext(Session session, String alias) throws Exception {
        UserSession userSession = (UserSession) session;
        Provider provider = getProvider(userSession);

        KeyManager[] kms = new KeyManager[] { new MTLSKeyManager(provider, alias) };
        TrustManager[] tms = new TrustManager[]{ new PermissiveTrustManager() };

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kms, tms, null);

        return sslContext;
    }

    public List<String> listKeys(Session session)
            throws Exception {
        UserSession userSession = (UserSession) session;
        Provider provider = getProvider(userSession);

        final KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(null, null);

        if (keyStore.size() == 0) {
            log.warn("Keystore is empty.");
            return List.of();
        }

        return Collections.list(keyStore.aliases());
    }

    public Key getKeyByLabel(Session session, String label)
            throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException {
        UserSession userSession = (UserSession) session;
        Provider provider = getProvider(userSession);

        final KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(null, null);
        return keyStore.getKey(label, null);
    }


    public String signPayload(Session session, String payload, String keyLabel, String algorithm) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, InvalidKeyException {
        UserSession userSession = (UserSession) session;
        Provider provider = getProvider(userSession);

        byte[] data = payload.getBytes(StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance(algorithm, provider);
        mac.init(getKeyByLabel(session, keyLabel));
        return bytesToHex(mac.doFinal(data));
    }

    public boolean verifySignature(Session session, String payload,String keyLabel, String algorithm, String signature) throws IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, CertificateException {
        String expectedSignature = signPayload(session, payload, keyLabel, algorithm);
        return expectedSignature.equals(signature);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private AuthProvider getProvider(UserSession session) {
        AuthProvider provider = userProviders.get(session.key());
        if (provider == null) {
            throw new IllegalStateException("User " + session.user() + " is not logged in.");
        }
        return provider;
    }
}