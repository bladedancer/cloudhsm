package com.matthews.poc.cloudhsm.provider.userprovider;

import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;
import com.amazonaws.cloudhsm.jce.jni.exception.ProviderInitializationException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmCluster;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmLoggingConfig;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProviderConfig;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmServer;
import com.amazonaws.cloudhsm.jce.provider.OptionalParameters;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
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

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AuthProvider;
import java.security.InvalidAlgorithmParameterException;
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
        UserSession session = new UserSession(user, clusterId);
        if (userProviders.containsKey(session.key())) {
            log.info("User {} is already logged in.", session.user());
            return session;
        }

        // Keying the provider by user name just as example.....
        String pkcs11Config = String.format("""
            name=CloudHSM_%s
            library=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so
            """, user);
        Path tempFile = Files.createTempFile("pkcs11Config", ".conf");
        Files.writeString(tempFile, pkcs11Config);

        AuthProvider provider = (AuthProvider) Security.getProvider("SunPKCS11").configure(tempFile.toString());

        provider.login(null, callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof javax.security.auth.callback.PasswordCallback passwordCallback) {
                    passwordCallback.setPassword(
                            String.format("%s:%s",
                                    StringUtil.isNullOrEmpty(user) ? defaultUser : user,
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

    public Key generateAESKey(Session session, int keySizeInBits, String keyLabel) throws IllegalStateException, AddAttributeException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        UserSession userSession = (UserSession) session;
        Provider provider = getProvider(userSession);

        KeyAttributesMap aesSpec = new KeyAttributesMap();
        aesSpec.put(KeyAttribute.LABEL, keyLabel);
        aesSpec.put(KeyAttribute.SIZE, keySizeInBits);
        aesSpec.put(KeyAttribute.TOKEN, true);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
        keyGen.init(aesSpec);
        return keyGen.generateKey();
    }

    public Key generateAESKey(
            Session session, int keySizeInBits, String keyLabel, KeyAttributesMap aesSpecKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException {
        UserSession userSession = (UserSession) session;
        Provider provider = getProvider(userSession);

        // Create an Aes keygen Algorithm parameter spec using KeyAttributesMap
        final KeyAttributesMap aesSpec = new KeyAttributesMap();
        aesSpec.putAll(aesSpecKeyAttributes);
        aesSpec.put(KeyAttribute.LABEL, keyLabel);
        aesSpec.put(KeyAttribute.SIZE, keySizeInBits);
        aesSpec.put(KeyAttribute.TOKEN, true);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider);
        keyGen.init(aesSpec);
        return keyGen.generateKey();
    }

    public List<String> listKeys(Session session)
            throws Exception {
        UserSession userSession = (UserSession) session;
        Provider provider = getProvider(userSession);

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
        Provider provider = getProvider(userSession);

        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE, provider);
        keyStore.load(null, null);
        return keyStore.getKey(label, null);
    }


    public String signPayload(Session session, String payload, String keyLabel, String algorithm) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException {
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

    private AuthProvider getProvider(UserSession session) {
        AuthProvider provider = userProviders.get(session.key());
        if (provider == null) {
            throw new IllegalStateException("User " + session.user() + " is not logged in.");
        }
        return provider;
    }
}