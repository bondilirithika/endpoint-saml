package com.example.flutto.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

@Configuration
public class SamlConfig {

    @Value("${saml.sp.entity-id}")
    private String spEntityId;

    @Value("${saml.acs.url}")
    private String acsUrl;

    @Value("${saml.google.entity-id}")
    private String googleEntityId;

    @Value("${saml.google.sso-url}")
    private String googleSsoUrl;

    @Value("${saml.google.certificate}")
    private String googleCertificate;

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        try {
            // Create a key pair for signing
            KeyPair keyPair = generateRsaKey();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            
            // Generate a self-signed certificate
            X509Certificate certificate = generateSelfSignedCertificate(keyPair);
            
            // Create signing credential with both private key and certificate
            Saml2X509Credential signingCredential = Saml2X509Credential.signing(privateKey, certificate);

            RelyingPartyRegistration registration = RelyingPartyRegistration
                    .withRegistrationId("google")
                    .entityId(spEntityId)
                    .assertionConsumerServiceLocation(acsUrl)
                    .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                    .assertingPartyMetadata(metadata -> metadata
                        .entityId(googleEntityId)
                        .singleSignOnServiceLocation(googleSsoUrl)
                        .singleSignOnServiceBinding(Saml2MessageBinding.REDIRECT)
                        .verificationX509Credentials(c -> c.add(getGoogleCertificate()))
                    )
                    .signingX509Credentials(c -> c.add(signingCredential))
                    .build();

            return new InMemoryRelyingPartyRegistrationRepository(registration);
            
        } catch (Exception e) {
            throw new RuntimeException("Error creating SAML configuration", e);
        }
    }

    private KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error generating RSA key pair", e);
        }
    }
    
    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair) {
        try {
            X500Name subject = new X500Name("CN=flutto-saml");
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date validFrom = new Date();
            Date validTo = new Date(validFrom.getTime() + 10 * 365 * 24 * 60 * 60 * 1000L); // 10 years
            
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, serialNumber, validFrom, validTo, subject, keyPair.getPublic());
            
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .build(keyPair.getPrivate());
            
            return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        } catch (Exception e) {
            throw new RuntimeException("Error generating self-signed certificate", e);
        }
    }

    private Saml2X509Credential getGoogleCertificate() {
        try {
            // Remove PEM headers and clean up the certificate
            String certContent = googleCertificate
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
                
            byte[] certificateBytes = Base64.getDecoder().decode(certContent);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(certificateBytes));
            return Saml2X509Credential.verification(certificate);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load Google SAML certificate", e);
        }
    }
}