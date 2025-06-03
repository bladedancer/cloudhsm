package com.matthews.poc.cloudhsm;

import com.amazonaws.cloudhsm.jce.jni.AuthenticationStrategy;
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
import com.amazonaws.cloudhsm.jce.provider.authentication.AuthenticationStrategyCallback;
import io.quarkus.runtime.Startup;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.crypto.KeyGenerator;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.AuthProvider;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

@ApplicationScoped
@Startup
@Slf4j
public class ProviderService {
    @ConfigProperty(name = "cloudhsm.clusterid")
    String clusterId;

    @ConfigProperty(name = "cloudhsm.cafile")
    String cafile;

    @ConfigProperty(name = "cloudhsm.ip")
    String ip;

    @ConfigProperty(name = "cloudhsm.port")
    Integer port;

    @ConfigProperty(name = "cloudhsm.user")
    String user;

    @ConfigProperty(name = "cloudhsm.password")
    String password;

    @PostConstruct
    public void init() throws Exception {
        log.info("Initializing CloudHSM provider service...");
        registerHsmProvider();
        login(user, password, clusterId);
    }

    @PreDestroy
    public void cleanup() {
        log.info("Cleaning up CloudHSM provider service...");
        try {
            AuthProvider provider = (AuthProvider) Security.getProvider(clusterId);
            if (provider != null) {
                provider.logout();
                Security.removeProvider(clusterId);
                log.info("CloudHSM provider removed successfully.");
            } else {
                log.warn("No CloudHSM provider found to remove.");
            }
        } catch (Exception e) {
            log.error("Error during cleanup: {}", e.getMessage(), e);
        }
    }

    /**
     * Generate an AES key with a specific label and keysize.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel Label to associate with the key.
     */
    public Key generateAESKey(int keySizeInBits, String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException {
        return generateAESKey(keySizeInBits, keyLabel, new KeyAttributesMap());
    }

    /**
     * Generate an AES key with a specific label and keysize.
     *
     * @param keySizeInBits Size of the key.
     * @param keyLabel Label to associate with the key.
     */
    public Key generateAESKey(
            int keySizeInBits, String keyLabel, KeyAttributesMap aesSpecKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException {

        // Create an Aes keygen Algorithm parameter spec using KeyAttributesMap
        final KeyAttributesMap aesSpec = new KeyAttributesMap();
        aesSpec.putAll(aesSpecKeyAttributes);
        aesSpec.put(KeyAttribute.LABEL, keyLabel);
        aesSpec.put(KeyAttribute.SIZE, keySizeInBits);

        KeyGenerator keyGen = KeyGenerator.getInstance("AES", clusterId);
        keyGen.init(aesSpec);
        return keyGen.generateKey();
    }

    private void registerHsmProvider() {
        try {
            CloudHsmProvider provider = createProvider(clusterId, cafile, ip, port);
            java.security.Security.addProvider(provider);
            log.info("CloudHSM provider registered successfully.");
        } catch (Exception e) {
            log.error("Failed to register CloudHSM provider: {}", e.getMessage(), e);
        }
    }

    private CloudHsmProvider createProvider(String clusterUniqueId,
                                            String caFilePath,
                                            String hostIp,
                                            Integer port) throws ProviderInitializationException, LoginException, IOException {
        final CloudHsmServer server = CloudHsmServer.builder()
                .withHostIP(hostIp)
                .withPort(port)
                .build();

        final CloudHsmCluster cluster = CloudHsmCluster.builder()
                .withClusterUniqueIdentifier(clusterUniqueId)
                .withHsmCAFilePath(caFilePath)
                .withOptions(OptionalParameters.VALIDATE_KEY_AT_INIT, false)
                .withOptions(OptionalParameters.KEY_AVAILABILITY_CHECK, true)
                .withServer(server)
                .build();

        final CloudHsmLoggingConfig loggingConfig = CloudHsmLoggingConfig.builder()
//                .withLogFile("/opt/cloudhsm/run/cloudhsm-jce.log")
//                .withLogInterval("daily")
//                .withLogType("file")
                .withLogLevel("debug")
                .build();

        final CloudHsmProviderConfig testConfig = CloudHsmProviderConfig.builder()
                .withCluster(cluster)
                .withCloudHsmLogging(loggingConfig)
                .build();
        return new CloudHsmProvider(testConfig);
    }

    public void login(String user, String password, String providerName) throws LoginException {
        AuthProvider provider = (AuthProvider) Security.getProvider(providerName);

        ApplicationCallBackHandler loginHandler = new ApplicationCallBackHandler(UserType.CRYPTO_USER, user, password);
        provider.login(null, loginHandler);
        log.info("Login successful on provider {} with user {}!", providerName, user);
    }

    @RequiredArgsConstructor
    static class ApplicationCallBackHandler implements CallbackHandler {
        private final UserType userType;
        private final String username;
        private final String password;

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof AuthenticationStrategyCallback asc) {
                    try {
                        asc.setAuthenticationStrategy(AuthenticationStrategy.createUsernamePasswordStrategy(userType, username, password.toCharArray()));
                    } catch (Exception e) {
                        throw new IOException(e);
                    }
                }
            }
        }
    }
}
