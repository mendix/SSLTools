package com.mendix.ssltools;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import java.io.IOException;

import static org.junit.Assert.*;

public class CertificateRequestTest extends BaseTest {
    @Test
    public void parseCertificateRequest() throws IOException {
        CertificateRequest certificateRequest = new CertificateRequest(CertificateRequest);
        PKCS10CertificationRequest csr = certificateRequest.getCertificateRequest();
        assertNotNull("Certificate request should not be null", csr);
        assertTrue("Should be able to get encoded form", 
            certificateRequest.getCertificateRequestInDerFormat().length > 0);
    }

    @Test
    public void generateNewCertificateRequest() throws Exception {
        PrivateKey privateKey = new PrivateKey(PrivateKey);
        String commonName = "hiernietpoepen.test.mendix.com";
        String organization = "Mendix";
        String locality = "Rotterdam";
        String state = "Zuid-Holland";
        String country = "NL";
        
        CertificateRequest certificateRequest = new CertificateRequest(
            privateKey, commonName, organization, null, locality, state, country);
            
        // Verify PEM format contains the expected markers
        String pem = certificateRequest.getCertificateRequestInPemFormat();
        assertTrue("PEM should contain BEGIN marker", pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assertTrue("PEM should contain END marker", pem.contains("-----END CERTIFICATE REQUEST-----"));
        
        // Verify we can parse the generated request
        CertificateRequest parsedRequest = new CertificateRequest(pem);
        assertNotNull("Should be able to parse generated request", parsedRequest);
    }
}
