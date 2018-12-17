package com.yunjingit.utils;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;
import java.util.Random;

public class Certifications {

    private static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    //String issuerString = "CN=root,OU=单位,O=组织";
    public static X509Certificate generateV3Certificate(String issuerString, String keyfile)
    {
        KeyPair keyPair= null;
        try {
            keyPair = Keys.generateRSAKeyPair(2048);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privKey = keyPair.getPrivate();

        //
        // distinguished name table.设置颁发者和主题
        //
        // X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        // builder.addRDN(BCStyle.C, "AU");
        // builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        // builder.addRDN(BCStyle.L, "Melbourne");
        //builder.addRDN(BCStyle.ST, "Victoria");
        // builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");
        // X500Name issueDn = builder.build();
        // X500Name subjectDn = builder.build();
        X500Name issueDn = new X500Name(issuerString);
        X500Name subjectDn = new X500Name(issuerString);

        // 设置开始日期和结束日期
        long year = 360 * 24 * 60 * 60 * 1000;
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + year);

        // 证书序列号
        BigInteger serial = BigInteger.probablePrime(32, new Random());

        //
        // create the certificate - version 3 - without extensions
        //
        X509Certificate cert=null;
        try {
            ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privKey); //自签名
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issueDn, serial, notBefore, notAfter, subjectDn, pubKey);
            //extensions
            certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, new X509KeyUsage(X509KeyUsage.encipherOnly));
            JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
            certGen.addExtension(
                    org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                    false,
                    utils.createSubjectKeyIdentifier(pubKey));

            certGen.addExtension(
                    org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                    false,
                    utils.createAuthorityKeyIdentifier(pubKey));

            certGen.addExtension(
                    org.bouncycastle.asn1.x509.Extension.basicConstraints,
                    true,
                    new BasicConstraints(0));

            cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));
        } catch (OperatorCreationException | CertificateException e) {
            e.printStackTrace();
        } catch (CertIOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            cert.checkValidity(new Date());
            cert.verify(pubKey);
            cert.verify(cert.getPublicKey());
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        //私钥保存到指定路径
        try{
            savePrivkey( keyfile, privKey);
        }catch(IOException e){
            e.printStackTrace();
        }


        return cert;

    }

    public static X509Certificate generateV3CertificateSM2(String issuerString, String keyfile){
        //
        // set up the keys
        //
        PrivateKey privKey;
        PublicKey pubKey;

        try
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

            g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

            KeyPair p = g.generateKeyPair();

            privKey = p.getPrivate();
            pubKey = p.getPublic();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }

        X500Name issueDn = new X500Name(issuerString);
        X500Name subjectDn = new X500Name(issuerString);

        // 设置开始日期和结束日期
        long year = 360 * 24 * 60 * 60 * 1000;
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + year);

        // 证书序列号
        BigInteger serial = BigInteger.probablePrime(32, new Random());

        ContentSigner sigGen = null;
        try {
            sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider(BC).build(privKey);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
            return null;
        }
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issueDn,
                serial,
                notBefore,
                notAfter,
                subjectDn,
                pubKey);

        X509Certificate cert = null;
        try {
            cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));
            cert.checkValidity(new Date());
            cert.verify(pubKey);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();

        }
        try{
            savePrivkey( keyfile, privKey);
        }catch(IOException e){
            e.printStackTrace();
        }

        return cert;

    }

    private static void savePrivkey(String keyfile, PrivateKey privKey) throws IOException{

        //私钥保存到指定路径
        FileOutputStream outputStream = null;

         outputStream = new FileOutputStream(keyfile);
         outputStream.write(privKey.getEncoded());//TODO: 私钥保存的格式
         outputStream.close();

    }


    public static boolean certificateVefity(X509Certificate cert){

        //verify
        try {
            cert.checkValidity(new Date());
        } catch (CertificateExpiredException e) {
            e.printStackTrace(); //TODO: 用log记录
            return false;
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
            return false;
        }

        //TODO: 证书签名验证


        //TODO: CRL & OCSP 证书状态验证

        return true;
    }


    public static Certificate readPEMCert(String pemData)
            throws CertificateException, UnsupportedEncodingException
    {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509", BC);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return cf.generateCertificate(new ByteArrayInputStream(pemData.getBytes("US-ASCII")));
    }

    public static List<? extends Certificate> readPEMCertPath(String pemData)
            throws CertificateException, UnsupportedEncodingException
    {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509", BC);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        CertPath cp= cf.generateCertPath(new ByteArrayInputStream(pemData.getBytes("US-ASCII")));
        List certs = cp.getCertificates();
        return certs;
    }

}
