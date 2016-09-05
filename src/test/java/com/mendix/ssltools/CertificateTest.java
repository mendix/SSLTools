package com.mendix.ssltools;

import org.junit.Test;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertTrue;

public class CertificateTest extends BaseTest {
    @Test
    public void parseTLSCertificate() throws CertificateException, IOException {
        Certificate certificate = new Certificate(TLSCertificate);
        X509Certificate x509 = certificate.getX509Certificate();
    }

    @Test(expected = CertificateException.class)
    public void parseInvalidTLSCertificate() throws CertificateException, IOException {
        Certificate certificate = new Certificate(invalidTLSCertificate);
        X509Certificate x509 = certificate.getX509Certificate();
    }

    @Test
    public void certificatePemToDerToPem() throws CertificateException, IOException {
        Certificate certificateFromPem = new Certificate(TLSCertificate);
        byte [] der = certificateFromPem.getCertificateInDerFormat();

        Certificate certificateFromDer = new Certificate(der);
        String pem = certificateFromDer.getCertificateInPemFormat();

        assertTrue(pem.equals(TLSCertificate));
    }

    @Test
    public void testKeyMatchBetweenCertificateAndPrivateKey() throws CertificateException, IOException {
        Certificate certificate = new Certificate(TLSCertificate);
        PrivateKey privateKey = new PrivateKey(PrivateKey);
        assertTrue(privateKey.matchCertificate(certificate));
    }
}
