package com.mendix.ssltools;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class CertificateRequest {
    private static final String BEGIN_MARKER = "-----BEGIN CERTIFICATE REQUEST-----";
    private static final String END_MARKER = "-----END CERTIFICATE REQUEST-----";

    private PKCS10 certificateRequest;

    public CertificateRequest(PrivateKey privateKey, String commonName, String organization,
                              String organizationalUnit, String locality, String stateOrProvince, String country)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, CertificateException, SignatureException {

        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey.getPrivateKey();
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS10 csr = new PKCS10(publicKey);
        if (commonName == null)
            commonName = "";
        if (organization == null)
            organization = "";
        if (organizationalUnit == null)
            organizationalUnit = "";
        if (locality == null)
            locality = "";
        if (stateOrProvince == null)
            stateOrProvince = "";
        if (country == null)
            country = "";
        X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, locality, stateOrProvince, country);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(rsaPrivateCrtKey);
        csr.encodeAndSign(x500Name, signature);
        this.certificateRequest = csr;
    }

    public CertificateRequest(byte[] der) throws NoSuchAlgorithmException, SignatureException, IOException {
        this.certificateRequest = new PKCS10(der);
    }

    public CertificateRequest(String pem) throws NoSuchAlgorithmException, SignatureException, IOException {
        Util util = new Util();
        byte[] der = util.readKeyMaterial(pem, BEGIN_MARKER, END_MARKER);
        this.certificateRequest = new PKCS10(der);
    }
    public String getCertificateRequestInPemFormat(){
        Util util = new Util();
        return util.derToPem(this.certificateRequest.getEncoded(), BEGIN_MARKER, END_MARKER);
    }

    public byte[] getCertificateRequestInDerFormat(){
        return this.certificateRequest.getEncoded();
    }

    public PKCS10 getPKCS10() {
        return this.certificateRequest;
    }
}
