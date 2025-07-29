package com.matthews.poc.cloudhsm.provider.userprovider;

import com.amazonaws.cloudhsm.jce.jni.UserType;
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
import com.matthews.poc.cloudhsm.controller.ApplicationCallbackHandler;
import io.quarkus.runtime.Startup;
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
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.login.LoginException;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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

    @ConfigProperty(name = "cloudhsm.clusterid")
    String clusterId;

    @ConfigProperty(name = "cloudhsm.cafile")
    String cafile;

    @ConfigProperty(name = "cloudhsm.ip")
    String ip;

    @ConfigProperty(name = "cloudhsm.port")
    Integer port;

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

        CloudHsmProvider provider = createProvider(clusterId, cafile, ip, port);
        ApplicationCallbackHandler loginHandler = new ApplicationCallbackHandler(UserType.CRYPTO_USER, user, password);
        provider.login(null, loginHandler);

        userProviders.put(session.key(), provider);
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

        // Load the key
        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE, provider);
        keyStore.load(null, null);
        Key key = keyStore.getKey(alias, null);

        if (key == null) {
            throw new KeyStoreException("No key found in the keystore with label " + alias);
        }

        // Load the certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate certificate;
        try (FileInputStream fis = new FileInputStream("./" + alias.replace("-key", "") + ".crt")) { // who needs security
            certificate = certFactory.generateCertificate(fis);
        }

        // Cant' do this: Create a KeyStore and add the key and certificate
        // keyStore.setKeyEntry(alias, key, null, new java.security.cert.Certificate[]{certificate});
        // KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        // kmf.init(keyStore, null);
        // So do this instead:
        KeyManager[] kms = new KeyManager[]{
                new X509ExtendedKeyManager() {
                    @Override
                    public String chooseEngineClientAlias(String[] keyType,
                                                          Principal[] issuers, SSLEngine engine) {
                        return alias;
                    }


                    @Override
                    public String[] getClientAliases(String keyType, Principal[] issuers) {
                        return new String[]{alias};
                    }

                    @Override
                    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                        return alias;
                    }

                    @Override
                    public String[] getServerAliases(String keyType, Principal[] issuers) {
                        return null;
                    }

                    @Override
                    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                        return null;
                    }

                    @Override
                    public X509Certificate[] getCertificateChain(String alias) {
                        return new X509Certificate[]{(X509Certificate) certificate};
                    }

                    @Override
                    public PrivateKey getPrivateKey(String alias) {
                        return (PrivateKey) key;
                    }
                }
        };

        // Just because I'm lazy - permissive trust manager
        TrustManager[] tms = new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs,
                                           String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs,
                                           String authType) {
            }
        }};


        // NOT CLOUD HSM PROVIDER
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(kms, tms, new SecureRandom());

        return sslContext;
    }

    public Key generateAESKey(Session session, int keySizeInBits, String keyLabel) throws IllegalStateException, AddAttributeException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        UserSession userSession = (UserSession) session;
        CloudHsmProvider provider = getProvider(userSession);

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
        CloudHsmProvider provider = getProvider(userSession);

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