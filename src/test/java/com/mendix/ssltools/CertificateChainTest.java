package com.mendix.ssltools;

import org.junit.Test;

import javax.naming.InvalidNameException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

public class CertificateChainTest extends BaseTest {
    @Test
    public void parseTLSCertificateChain() throws CertificateException, IOException, InvalidNameException {
        CertificateChain certificateChain = new CertificateChain(TLSCertificateChain);
    }

    @Test
    public void parseUnorderedTLSCertificateChain() throws CertificateException, NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, InvalidNameException {
        CertificateChain certificateChain = new CertificateChain(unorderedTLSCertificateChain);
    }

    @Test
    public void parseTLSCertificateChainWithTrailingNewline() throws CertificateException, IOException, InvalidNameException {
        CertificateChain certificateChain = new CertificateChain(TLSCertificateChainWithTrailingNewline);
    }

    @Test
    public void certificateMatchesCertificateChain() throws CertificateException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidNameException {
        Certificate certificate = new Certificate(TLSCertificate);
        CertificateChain certificateChain = new CertificateChain(TLSCertificateChain);
        certificateChain.matchCertificate(certificate);
    }
}
