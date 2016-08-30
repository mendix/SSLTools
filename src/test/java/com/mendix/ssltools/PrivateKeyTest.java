package com.mendix.ssltools;

import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertTrue;

public class PrivateKeyTest extends BaseTest {
    @Test
    public void parseValidPrivateKey() throws IOException {
        PrivateKey privateKey = new PrivateKey(validPrivateKey);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey.getPrivateKey();
    }

    @Test(expected = IOException.class)
    public void parseInvalidTLSCertificate() throws CertificateException, IOException {
        PrivateKey privateKey = new PrivateKey(invalidPrivateKey);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey.getPrivateKey();
    }

    @Test
    public void privateKeyPemToDerToPem() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKeyFromPem = new PrivateKey(validPrivateKey);
        byte [] der = privateKeyFromPem.getPrivateKeyInDerFormat();
        BigInteger modulusFromPem = privateKeyFromPem.getModulus();

        PrivateKey privateKeyFromDer = new PrivateKey(der);
        BigInteger modulusFromDer = privateKeyFromDer.getModulus();

        assertTrue(modulusFromPem.equals(modulusFromDer));
    }

    @Test
    public void getValidPublicKeyFromPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        PrivateKey privateKey = new PrivateKey(validPrivateKey);
        PublicKey publicKey = privateKey.getPublicKeyFromPrivateKey();
    }
}
