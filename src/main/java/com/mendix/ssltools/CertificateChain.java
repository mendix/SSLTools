package com.mendix.ssltools;

import javax.naming.InvalidNameException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CertificateChain {
    private List<Certificate> certificateList;

    public CertificateChain(String pemChain) throws CertificateException, IOException, InvalidNameException {
        this.certificateList = this.parseCertificateChain(pemChain);
        this.certificateList = orderCertificateChain(this.certificateList);
    }

    private List<Certificate> parseCertificateChain(String pemChain) throws CertificateException, IOException {
        String END_MARKER = "-----END CERTIFICATE-----";
        List<Certificate> crtList = new ArrayList<>();
        String[] pemCerts = pemChain.split(END_MARKER);
        for (String pemCert: pemCerts){
            Certificate certificate = new Certificate(pemCert + END_MARKER);
            crtList.add(certificate);
        }
        return crtList;
    }

    public List<Certificate> orderCertificateChain(List<Certificate> unorderedCertificateList) throws CertificateException, InvalidNameException {
        if (this.certificateList.size() <= 1) {
            return unorderedCertificateList;
        }

        List<Certificate> orderedCertificateList = new ArrayList<>();

        Certificate topCertificate = findTopCertificate(unorderedCertificateList);
        orderedCertificateList.add(topCertificate);
        unorderedCertificateList.remove(topCertificate);

        Integer count = unorderedCertificateList.size();
        for (int i = 0; i < count ; i++) {
            Certificate nextCertificate = findNextCertificate(orderedCertificateList.get(0), unorderedCertificateList);
            orderedCertificateList.add(0, nextCertificate);
            unorderedCertificateList.remove(nextCertificate);
        }
        return orderedCertificateList;
    }

    private Certificate findTopCertificate (List<Certificate> certificateList) throws CertificateException {
        for (Certificate currentCert: certificateList) {
            Boolean signerFound = false;
            for (Certificate certificate: certificateList) {
                if (currentCert != certificate) {
                    try {
                        currentCert.getX509Certificate().verify(certificate.getX509Certificate().getPublicKey());
                        signerFound = true;
                        continue;
                    } catch (SignatureException | InvalidKeyException |
                            CertificateException | NoSuchAlgorithmException |
                            NoSuchProviderException e) {
                    }
                }
            }
            if (!signerFound) {
                return currentCert;
            }
        }
        throw new CertificateException("Could not find the top of the chain.");
    }

    private Certificate findNextCertificate (Certificate certificate, List<Certificate> certificateList) throws CertificateException, InvalidNameException {
        for (Certificate currentCert: certificateList) {
            try {
                currentCert.getX509Certificate().verify(certificate.getX509Certificate().getPublicKey());
                return currentCert;
            } catch (SignatureException | InvalidKeyException |
                    CertificateException | NoSuchAlgorithmException |
                    NoSuchProviderException e) {
            }
        }
        throw new CertificateException("Chain doesn't contain a certificate that was signed by: '" + certificate.getCommonName() + "'");
    }

    public Boolean matchCertificate(Certificate certificate) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (this.certificateList.size() == 0) {
            return false;
        }
        X509Certificate x509cert = certificate.getX509Certificate();
        x509cert.verify(this.certificateList.get(0).getX509Certificate().getPublicKey());
        return true;
    }

    public String getCertificateChainInPemFormat() throws CertificateEncodingException {
        String result = "";
        for (Certificate certificate: this.certificateList) {
            result += certificate.getCertificateInPemFormat() + "\n";
        }
        return result;
    }

    public byte[] getCertificateChainInDerFormat() throws IOException, CertificateEncodingException {
        byte[] result = new byte[0];
        for (Certificate certificate: this.certificateList) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(result);
            outputStream.write(certificate.getCertificateInDerFormat());
            result = outputStream.toByteArray();
        }
        return result;
    }

    public List<Certificate> getCertificateList () {
        return this.certificateList;
    }
}
