package com.matthews.poc.cloudhsm.provider.userprovider;

import com.amazonaws.cloudhsm.jce.jni.exception.AddAttributeException;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyPairAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyType;
import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.management.openmbean.InvalidKeyException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;


@ApplicationScoped
@Named("JCE")
@Startup
@Slf4j
public class KeyService {

    // Based on: https://github.com/aws-samples/aws-cloudhsm-jce-examples/blob/sdk5/src/main/java/com/amazonaws/cloudhsm/examples/KeyStoreExampleRunner.java
    public void createKeystore(Provider provider, final String keystoreFile, final String password, final String labelArg) throws Exception {

        final String label;
        label = Objects.requireNonNullElse(labelArg, "demoKeyPair");

        final String privateLabel = label + ":Private";

        final KeyStore keyStore = KeyStore.getInstance(CloudHsmProvider.CLOUDHSM_KEYSTORE_TYPE, provider);
        try {
            final FileInputStream instream = new FileInputStream(keystoreFile);
            // This call to keyStore.load() will open the CloudHSM keystore file with the supplied
            // password.
            keyStore.load(instream, password.toCharArray());
        } catch (final FileNotFoundException ex) {
            log.error("Keystore not found, loading an empty store");
            keyStore.load(null, null);
        }

        final KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(password.toCharArray());
        log.info("Searching for example key pair and certificate...");

        /*
         * Generates the key pair if not found and signs a certificate with the key and stores it in the
         * KeyStore.
         */
        if (!keyStore.containsAlias(privateLabel)) {
            log.info("No entry found for '" + privateLabel + "', creating a keypair...");
            final KeyPair keyPair = generateRSAKey(provider, 2048, label);

            /** Generate a certificate and associate the chain with the private key. */
            final Certificate selfSignedCert = createAndSignCertificate(keyPair, provider);
            final Certificate[] chain = new Certificate[]{selfSignedCert};
            final PrivateKeyEntry entry = new PrivateKeyEntry(keyPair.getPrivate(), chain);
            keyStore.setEntry(privateLabel, entry, passwordProtection);

            final FileOutputStream outstream = new FileOutputStream(keystoreFile);
            keyStore.store(outstream, password.toCharArray());
            outstream.close();
        }

        final PrivateKeyEntry keyEntry =
                (PrivateKeyEntry) keyStore.getEntry(privateLabel, passwordProtection);
        final String name = keyEntry.getCertificate().toString();
        log.info("Found private key with label %s and certificate {} {}", label, name);
    }

    /**
     * Generate a certificate signed by a given keypair.
     */
    private Certificate createAndSignCertificate(final KeyPair keyPair, Provider provider)
            throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException,
            SignatureException, InvalidKeyException, OperatorCreationException {
        final X500Name x500Name =
                new X500Name("C=US, ST=Washington, L=Seattle, O=Amazon, OU=AWS, CN=CloudHSM");

        // Serial number should be unique per CA
        final long serialNumberValue = System.currentTimeMillis() % Long.MAX_VALUE;
        final BigInteger serialNumber = BigInteger.valueOf(serialNumberValue);
        final Calendar calendar = Calendar.getInstance();

        final String keyAlgorithm = keyPair.getPrivate().getAlgorithm();
        final SubjectPublicKeyInfo publicKeyInfo =
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        final X500Name issuer = x500Name;
        final X500Name subject = x500Name;
        final Date notValidUntil = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        final Date notValidAfter = calendar.getTime();
        final X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(
                        issuer, serialNumber, notValidUntil, notValidAfter, subject, publicKeyInfo);

        final String signatureAlgorithm;
        if (keyAlgorithm.equalsIgnoreCase("RSA")) {
            signatureAlgorithm = "SHA512WithRSA";
        } else {
            throw new IllegalArgumentException(
                    "KeyAlgorithm should be RSA, but found " + keyAlgorithm);
        }

        final ContentSigner signer =
                new JcaContentSignerBuilder(signatureAlgorithm)
                        .setProvider(provider)
                        .build(keyPair.getPrivate());
        final X509CertificateHolder certificateHolder = builder.build(signer);
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(certificateHolder);
    }

    public KeyPair generateRSAKey(Provider provider, int keySizeInBits, String keyLabel) throws AddAttributeException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyPairAttributesMap rsaSpec = (new KeyPairAttributesMapBuilder())
                .withPublic(
                        (new KeyAttributesMapBuilder())
                                .put(KeyAttribute.TOKEN, true)
                                .put(KeyAttribute.ENCRYPT, true)
                                .put(KeyAttribute.VERIFY, true)
                                .put(KeyAttribute.WRAP, true)
                                .put(KeyAttribute.LABEL, keyLabel + ":Public")
                                .put(KeyAttribute.MODULUS_BITS, keySizeInBits)
                                .put(KeyAttribute.KEY_TYPE, KeyType.RSA)
                                .put(KeyAttribute.PUBLIC_EXPONENT, BigInteger.valueOf(65537).toByteArray())
                                .build())
                .withPrivate(
                        (new KeyAttributesMapBuilder())
                                .put(KeyAttribute.TOKEN, true)
                                .put(KeyAttribute.PRIVATE, true)
                                .put(KeyAttribute.EXTRACTABLE, true)
                                .put(KeyAttribute.DECRYPT, true)
                                .put(KeyAttribute.SIGN, true)
                                .put(KeyAttribute.UNWRAP, true)
                                .put(KeyAttribute.LABEL, keyLabel + ":Private")
                                .put(KeyAttribute.KEY_TYPE, KeyType.RSA)
                                .build())
                .build();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);
        generator.initialize(rsaSpec);

        return generator.generateKeyPair();
    }
}
