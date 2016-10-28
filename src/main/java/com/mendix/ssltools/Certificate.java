package com.mendix.ssltools;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;

public class Certificate {
    private static final String BEGIN_MARKER = "-----BEGIN CERTIFICATE-----";
    private static final String END_MARKER = "-----END CERTIFICATE-----";

    private X509Certificate certificate;

    public Certificate(String pem) throws CertificateException, IOException {
        Util util = new Util();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream tlsStream = new ByteArrayInputStream(util.readKeyMaterial(pem, BEGIN_MARKER, END_MARKER));
        this.certificate = (X509Certificate) cf.generateCertificate(tlsStream);
    }

    public Certificate(byte[] der) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream tlsStream = new ByteArrayInputStream(der);
        this.certificate = (X509Certificate) cf.generateCertificate(tlsStream);
    }

    public String getCertificateInPemFormat() throws CertificateEncodingException {
        Util util = new Util();
        return util.derToPem(this.certificate.getEncoded(), BEGIN_MARKER, END_MARKER);
    }

    public byte[] getCertificateInDerFormat() throws CertificateEncodingException {
        return this.certificate.getEncoded();
    }

    public X509Certificate getX509Certificate() {
        return this.certificate;
    }

    public BigInteger getModulus() {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) this.certificate.getPublicKey();
        return rsaPublicKey.getModulus();
    }

    public String getCommonName() throws InvalidNameException {
        LdapName DN = new LdapName(getX509Certificate().getSubjectX500Principal().getName());
        return getFromDN(DN, "CN");
    }

    public String getSubjectAlternativeName() throws CertificateParsingException {
        Collection<List<?>> subAltNames = getX509Certificate().getSubjectAlternativeNames();
        String san = "";
        if (subAltNames != null) {
            for (List<?> subAltName : subAltNames) {
                if (subAltName.get(0).toString().equals("2")) {
                    san += subAltName.get(1).toString() + ", ";
                }
            }
        }
        if (san != "" && san.endsWith(", ")) {
            san = san.substring(0, san.length() - 2);
        } else {
            san = null;
        }
        return san;
    }

    public String getOrganization() throws InvalidNameException {
        LdapName DN = new LdapName(getX509Certificate().getSubjectX500Principal().getName());
        return getFromDN(DN, "O");
    }

    public String getOrganizationalUnit() throws InvalidNameException {
        LdapName DN = new LdapName(getX509Certificate().getSubjectX500Principal().getName());
        return getFromDN(DN, "OU");
    }

    public String getIssuerCommonName() throws InvalidNameException {
        LdapName issuerDN = new LdapName(getX509Certificate().getIssuerDN().getName());
        return getFromDN(issuerDN, "CN");
    }

    public String getIssuerOrganization() throws InvalidNameException {
        LdapName issuerDN = new LdapName(getX509Certificate().getIssuerDN().getName());
        return getFromDN(issuerDN, "O");
    }

    public String getIssuerOrganizationalUnit() throws InvalidNameException {
        LdapName issuerDN = new LdapName(getX509Certificate().getIssuerDN().getName());
        return getFromDN(issuerDN, "OU");
    }

    private String getFromDN(LdapName DN, String name) throws InvalidNameException {
        String result = null;
        for (Rdn rdn : DN.getRdns()) {
            if (rdn.toString().startsWith(name + "=") && !rdn.toString().equals(name + "=")) {
                result = rdn.toString().split(name + "=")[1];
            }
        }
        return result;
    }

    public Date getNotBefore() {
        return getX509Certificate().getNotBefore();
    }

    public Date getNotAfter() {
        return getX509Certificate().getNotAfter();
    }

    public String getSignatureAlgorithm() {
        return getX509Certificate().getSigAlgName();
    }

    public String getSha1Fingerprint() throws CertificateEncodingException, NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(getCertificateInDerFormat());
        Util util = new Util();
        return util.toHex(sha1.digest());
    }

    public String getSha256Fingerprint() throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(getCertificateInDerFormat());
        Util util = new Util();
        return util.toHex(sha256.digest());
    }
}
