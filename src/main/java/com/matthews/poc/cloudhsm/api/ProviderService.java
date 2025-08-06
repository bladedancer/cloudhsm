package com.matthews.poc.cloudhsm.api;

import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * Interface for interacting with a CloudHSM provider.
 * Provides methods for key management, authentication, and cryptographic operations.
 */
public interface ProviderService {

    /**
     * Authenticates a user to the HSM provider.
     *
     * @param user The username for authentication.
     * @param password The password for authentication.
     * @throws Exception If authentication fails.
     */
    Session login(String user, String password) throws Exception;

    void logout(Session session) throws Exception;

    String createKeystore(Session session, String alias) throws Exception;

    /**
     * Get the SSL Context for the given session.
     * @param session
     * @return
     * @throws Exception
     */
    SSLContext getSSLContext(Session session, String alias) throws Exception;

    /**
     * Generate an RSA Key pair.
     *
     * @param session
     * @param keySizeInBits
     * @param keyLabel
     * @return
     * @throws Exception
     */
    KeyPair generateRSAKey(Session session, int keySizeInBits, String keyLabel) throws Exception;

    /**
     * Generates an AES key with the specified size and label.
     *
     * @param keySizeInBits The size of the AES key in bits.
     * @param keyLabel The label to associate with the generated key.
     * @return The generated AES key.
     * @throws InvalidAlgorithmParameterException If the algorithm parameters are invalid.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     * @throws NoSuchProviderException If the provider is not available.
     * @throws AddAttributeException If there is an error adding attributes to the key.
     */
    Key generateAESKey(Session session, int keySizeInBits, String keyLabel)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException, IllegalStateException;

    /**
     * Generates an AES key with the specified size, label, and additional attributes.
     *
     * @param keySizeInBits The size of the AES key in bits.
     * @param keyLabel The label to associate with the generated key.
     * @param aesSpecKeyAttributes Additional attributes for the key.
     * @return The generated AES key.
     * @throws InvalidAlgorithmParameterException If the algorithm parameters are invalid.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     * @throws NoSuchProviderException If the provider is not available.
     * @throws AddAttributeException If there is an error adding attributes to the key.
     */
    Key generateAESKey(
            Session session,
            int keySizeInBits, String keyLabel, KeyAttributesMap aesSpecKeyAttributes)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException, AddAttributeException;

    /**
     * Lists all keys available in the HSM.
     *
     * @return A list of key labels.
     * @throws Exception If an error occurs while listing keys.
     */
    List<String> listKeys(Session session) throws Exception;

    /**
     * Retrieves a key by its label.
     *
     * @param label The label of the key to retrieve.
     * @return The key associated with the specified label.
     * @throws CertificateException If there is an error with the certificate.
     * @throws IOException If an I/O error occurs.
     * @throws NoSuchAlgorithmException If the algorithm is not available.
     * @throws KeyStoreException If there is an error with the keystore.
     * @throws UnrecoverableKeyException If the key cannot be recovered.
     */
    Key getKeyByLabel(Session session, String label)
            throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException;

    /**
     * Signs a payload using the specified key and algorithm.
     *
     * @param payload The payload to sign.
     * @param keyLabel The label of the key to use for signing.
     * @param algorithm The algorithm to use for signing.
     * @return The generated signature.
     * @throws CertificateException If there is an error with the certificate.
     * @throws IOException If an I/O error occurs.
     * @throws NoSuchAlgorithmException If the algorithm is not available.
     * @throws KeyStoreException If there is an error with the keystore.
     * @throws UnrecoverableKeyException If the key cannot be recovered.
     * @throws InvalidKeyException If the key is invalid.
     * @throws NoSuchProviderException If the provider is not available.
     */
    String signPayload(Session session, String payload, String keyLabel, String algorithm) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException;

    /**
     * Verifies a signature for a given payload using the specified key and algorithm.
     *
     * @param payload The payload to verify.
     * @param keyLabel The label of the key to use for verification.
     * @param algorithm The algorithm to use for verification.
     * @param signature The signature to verify.
     * @return True if the signature is valid, false otherwise.
     * @throws IOException If an I/O error occurs.
     * @throws NoSuchAlgorithmException If the algorithm is not available.
     * @throws KeyStoreException If there is an error with the keystore.
     * @throws UnrecoverableKeyException If the key cannot be recovered.
     * @throws InvalidKeyException If the key is invalid.
     * @throws NoSuchProviderException If the provider is not available.
     * @throws CertificateException If there is an error with the certificate.
     */
    boolean verifySignature(Session session, String payload, String keyLabel, String algorithm, String signature) throws IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, CertificateException;

}