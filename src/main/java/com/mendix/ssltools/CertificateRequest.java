package com.mendix.ssltools;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class CertificateRequest {
    private static final String BEGIN_MARKER = "-----BEGIN CERTIFICATE REQUEST-----";
    private static final String END_MARKER = "-----END CERTIFICATE REQUEST-----";

    private PKCS10CertificationRequest certificateRequest;

    /**
     * @deprecated Use the constructor that takes com.mendix.ssltools.PrivateKey instead
     */
    @Deprecated
    public CertificateRequest(PrivateKey privateKey, String commonName, String organization,
                           String organizationalUnit, String locality, String stateOrProvince, String country)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, 
                   CertificateException, OperatorCreationException {
        this(new com.mendix.ssltools.PrivateKey(privateKey.getEncoded()), 
             commonName, organization, organizationalUnit, locality, stateOrProvince, country);
    }
    
    public CertificateRequest(com.mendix.ssltools.PrivateKey privateKey, String commonName, String organization,
                           String organizationalUnit, String locality, String stateOrProvince, String country)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, 
                   CertificateException, OperatorCreationException {
        // Initialize the certificate request
        this.certificateRequest = createCertificateRequest(privateKey, commonName, organization, 
            organizationalUnit, locality, stateOrProvince, country);
    }
    
    private PKCS10CertificationRequest createCertificateRequest(com.mendix.ssltools.PrivateKey privateKey, 
            String commonName, String organization, String organizationalUnit, 
            String locality, String stateOrProvince, String country)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, 
                   OperatorCreationException {
        
        // Get the private key
        java.security.PrivateKey rsaPrivateKey = privateKey.getPrivateKey();
        if (!(rsaPrivateKey instanceof RSAPrivateCrtKey)) {
            throw new InvalidKeyException("Only RSA private keys are supported");
        }
        
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) rsaPrivateKey;
        
        // Generate public key from private key
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
            rsaPrivateCrtKey.getModulus(), 
            rsaPrivateCrtKey.getPublicExponent()
        );
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        // Build subject
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        if (commonName != null) nameBuilder.addRDN(BCStyle.CN, commonName);
        if (organization != null) nameBuilder.addRDN(BCStyle.O, organization);
        if (organizationalUnit != null) nameBuilder.addRDN(BCStyle.OU, organizationalUnit);
        if (locality != null) nameBuilder.addRDN(BCStyle.L, locality);
        if (stateOrProvince != null) nameBuilder.addRDN(BCStyle.ST, stateOrProvince);
        if (country != null) nameBuilder.addRDN(BCStyle.C, country);
        
        X500Name subject = nameBuilder.build();
        
        // Create the certification request
        String signatureAlgorithm = "SHA256withRSA";
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
            .build(rsaPrivateKey);
            
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
            subject, publicKey);
            
        return p10Builder.build(signer);
    }

    public CertificateRequest(byte[] der) throws IOException {
        this.certificateRequest = new PKCS10CertificationRequest(der);
    }

    public CertificateRequest(String pem) throws IOException {
        Util util = new Util();
        byte[] der = util.readKeyMaterial(pem, BEGIN_MARKER, END_MARKER);
        this.certificateRequest = new PKCS10CertificationRequest(der);
    }
    public String getCertificateRequestInPemFormat() {
        Util util = new Util();
        try {
            return util.derToPem(this.certificateRequest.getEncoded(), BEGIN_MARKER, END_MARKER);
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode certificate request", e);
        }
    }

    public byte[] getCertificateRequestInDerFormat() {
        try {
            return this.certificateRequest.getEncoded();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode certificate request", e);
        }
    }

    /**
     * @deprecated This method is no longer supported in Java 17+ as it relies on internal Sun APIs.
     * Use {@link #getCertificateRequest()} instead which returns a Bouncy Castle PKCS10CertificationRequest.
     * @return null as this method is no longer supported
     * @throws UnsupportedOperationException when called, as this method is no longer supported
     */
    @Deprecated
    public Object getPKCS10() {
        throw new UnsupportedOperationException("getPKCS10() is no longer supported. Use getCertificateRequest() instead.");
    }
    
    /**
     * Returns the PKCS#10 certificate request in Bouncy Castle format.
     * @return The Bouncy Castle PKCS10CertificationRequest object
     */
    public PKCS10CertificationRequest getCertificateRequest() {
        return certificateRequest;
    }
}
