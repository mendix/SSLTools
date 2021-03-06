package com.mendix.ssltools;

import org.junit.Test;
import sun.security.pkcs10.PKCS10;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertTrue;

public class CertificateRequestTest extends BaseTest {
    @Test
    public void parseCertificateRequest() throws NoSuchAlgorithmException, SignatureException, IOException {
        CertificateRequest certificateRequest = new CertificateRequest(CertificateRequest);
        PKCS10 pkcs10 = certificateRequest.getPKCS10();
    }

    @Test
    public void generateNewCertificateRequest() throws NoSuchAlgorithmException, SignatureException, IOException, CertificateException, InvalidKeySpecException, InvalidKeyException {
        PrivateKey privateKey = new PrivateKey(PrivateKey);
        CertificateRequest certificateRequest = new CertificateRequest(
                privateKey, "hiernietpoepen.test.mendix.com", "Mendix", null, "Rotterdam", "Zuid-Holland", "NL");
        assertTrue(certificateRequest.getCertificateRequestInPemFormat().equals(CertificateRequest));
    }
}
