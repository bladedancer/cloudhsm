package com.matthews.poc.cloudhsm.provider.userprovider;

import com.amazonaws.cloudhsm.jce.jni.UserType;
import com.amazonaws.cloudhsm.jce.jni.exception.ProviderInitializationException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmCluster;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmLoggingConfig;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProviderConfig;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmServer;
import com.amazonaws.cloudhsm.jce.provider.OptionalParameters;
import com.matthews.poc.cloudhsm.api.ProviderService;
import com.matthews.poc.cloudhsm.api.Session;
import com.matthews.poc.cloudhsm.controller.ApplicationCallbackHandler;
import io.quarkus.runtime.Startup;
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
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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
    private final Map<String, CloudHsmProvider> userProviders = new ConcurrentHashMap<>();

    @ConfigProperty(name = "cloudhsm.cafile")
    String cafile;

    @ConfigProperty(name = "cloudhsm.ip")
    String ip;

    @ConfigProperty(name = "cloudhsm.port")
    Integer port;

    @ConfigProperty(name = "cloudhsm.user")
    private String defaultUser;

    @ConfigProperty(name = "cloudhsm.password")
    private String defaultPassword;

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
        user = (user != null) ? user : defaultUser;
        password = (password != null) ? password : defaultPassword;

        UserSession session = new UserSession(user);
        if (userProviders.containsKey(session.key())) {
            log.info("User {} is already logged in.", session.user());
            return session;
        }

        CloudHsmProvider provider = createProvider(session.key(), cafile, ip, port);
        ApplicationCallbackHandler loginHandler = new ApplicationCallbackHandler(UserType.CRYPTO_USER, user, password);
        provider.login(null, loginHandler);

        userProviders.put(session.key(), provider);
        Security.addProvider(provider);
        log.info("User {} logged in successfully.", user);
        return session;
    }

    public void logout(Session session) {
        UserSession userSession = (UserSession) session;

        CloudHsmProvider provider = userProviders.remove(userSession.key());
        if (provider != null) {
            try {
                provider.logout();
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
        CloudHsmProvider provider = getProvider(userSession);

        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE, provider);
        keyStore.load(null, null);
        KeyManager[] kms = new KeyManager[] { new KeystoreKeyManager(keyStore, alias) };
        TrustManager[] tms = new TrustManager[]{ new PermissiveTrustManager() };

        // NOT CLOUD HSM PROVIDER
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(kms, tms, null);

        return sslContext;
    }

    public List<String> listKeys(Session session)
            throws Exception {
        UserSession userSession = (UserSession) session;
        CloudHsmProvider provider = getProvider(userSession);

        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE, provider);
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
        CloudHsmProvider provider = getProvider(userSession);

        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE, provider);
        keyStore.load(null, null);
        return keyStore.getKey(label, null);
    }


    public String signPayload(Session session, String payload, String keyLabel, String algorithm) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException {
        UserSession userSession = (UserSession) session;
        CloudHsmProvider provider = getProvider(userSession);

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


    private CloudHsmProvider createProvider(String clusterUniqueId, String caFilePath, String hostIp, Integer port)
            throws ProviderInitializationException, IOException, LoginException {
        CloudHsmServer server = CloudHsmServer.builder()
                .withHostIP(hostIp)
                .withPort(port)
                .build();

        CloudHsmCluster cluster = CloudHsmCluster.builder()
                .withClusterUniqueIdentifier(clusterUniqueId)
                .withHsmCAFilePath(caFilePath)
                .withOptions(OptionalParameters.VALIDATE_KEY_AT_INIT, false)
                .withOptions(OptionalParameters.KEY_AVAILABILITY_CHECK, true)
                .withServer(server)
                .build();

        CloudHsmLoggingConfig loggingConfig = CloudHsmLoggingConfig.builder()
                .withLogType("term")
                .withLogLevel("debug")
                .build();

        CloudHsmProviderConfig config = CloudHsmProviderConfig.builder()
                .withCluster(cluster)
                .withCloudHsmLogging(loggingConfig)
                .build();

        return new CloudHsmProvider(config);
    }

    private CloudHsmProvider getProvider(UserSession session) {
        CloudHsmProvider provider = userProviders.get(session.key());
        if (provider == null) {
            throw new IllegalStateException("User " + session.user() + " is not logged in.");
        }
        return provider;
    }
}