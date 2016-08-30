package com.mendix.ssltools;

import org.junit.Test;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertTrue;

public class CertificateTest extends BaseTest {
    @Test
    public void parseValidTLSCertificate() throws CertificateException, IOException {
        Certificate certificate = new Certificate(validTLSCertificate);
        X509Certificate x509 = certificate.getX509Certificate();
    }

    @Test(expected = CertificateException.class)
    public void parseinValidTLSCertificate() throws CertificateException, IOException {
        Certificate certificate = new Certificate(invalidTLSCertificate);
        X509Certificate x509 = certificate.getX509Certificate();
    }

    @Test
    public void certificatePemToDerToPem() throws CertificateException, IOException {
        Certificate certificateFromPem = new Certificate(validTLSCertificate);
        byte [] der = certificateFromPem.getCertificateInDerFormat();

        Certificate certificateFromDer = new Certificate(der);
        String pem = certificateFromDer.getCertificateInPemFormat();

        assertTrue(pem.equals(validTLSCertificate));
    }

    @Test
    public void testKeyMatchBetweenCertificateAndPrivateKey() throws CertificateException, IOException {
        Certificate certificate = new Certificate(validTLSCertificate);
        PrivateKey privateKey = new PrivateKey(validPrivateKey);
        assertTrue(privateKey.matchCertificate(certificate));
    }
}
