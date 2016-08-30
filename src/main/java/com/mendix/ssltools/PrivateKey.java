package com.mendix.ssltools;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class PrivateKey {
    public static final String P1_BEGIN_MARKER = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String P1_END_MARKER = "-----END RSA PRIVATE KEY-----";
    public static final String P8_BEGIN_MARKER = "-----BEGIN PRIVATE KEY-----";
    public static final String P8_END_MARKER = "-----END PRIVATE KEY-----";

    private java.security.PrivateKey privateKey;

    public PrivateKey(int size) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(size);
        KeyPair keypair = generator.generateKeyPair();
        this.privateKey = keypair.getPrivate();
    }

    public PrivateKey(String pem) throws IOException {
        PrivateKeyReader pkr = new PrivateKeyReader(pem);
        this.privateKey = pkr.read();
    }

    public PrivateKey(byte[] der) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        try {
            PrivateKeyReader privateKeyReader = new PrivateKeyReader("");
            RSAPrivateCrtKeySpec spec = privateKeyReader.getRSAKeySpec(der);
            this.privateKey = kf.generatePrivate(spec);
        } catch (IOException i) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            this.privateKey = kf.generatePrivate(spec);
        }
    }

    public String getPrivateKeyInPKCS1PemFormat() {
        Util util = new Util();
        return util.derToPem(this.privateKey.getEncoded(), P8_BEGIN_MARKER, P8_END_MARKER);
    }

    public byte[] getPrivateKeyInDerFormat() {
        return this.privateKey.getEncoded();
    }

    public java.security.PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public BigInteger getModulus() {
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) this.privateKey;
        return rsaPrivateKey.getModulus();
    }

    public PublicKey getPublicKeyFromPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) this.privateKey;
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) rsaPrivateKey;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicKeySpec);
    }

    public Boolean matchCertificate(Certificate certificate) {
        X509Certificate x509 = certificate.getX509Certificate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) x509.getPublicKey();
        BigInteger publicKeyModulus = rsaPublicKey.getModulus();

        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) this.privateKey;
        BigInteger privateKeyModulus = rsaPrivateKey.getModulus();

        return publicKeyModulus.equals(privateKeyModulus);
    }
}
