package com.yunjingit.utils;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
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
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

public class Certifications {

    private static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
    private static ArrayList<Certificate> certlist = new ArrayList<Certificate>();
    private static ArrayList<CRL> crllist = new ArrayList<CRL>();
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    //String issuerString = "CN=root,OU=单位,O=组织";
    public static X509Certificate generateV3Certificate(String issuerString, String keyfile, String certfile)
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


        long year = 360 * 24 * 60 * 60 * 1000;
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + year);


        BigInteger serial = BigInteger.probablePrime(32, new Random());

        //
        // create the certificate - version 3 - without extensions
        //
        X509Certificate cert=null;
        try {
            ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(privKey); //self-signed SHA256WithRSAEncryption
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
        } catch (Exception e) {
            e.printStackTrace();
        }

        //save to file
        try{
            savePrivkey( keyfile, privKey);
            saveCertificate( certfile, cert);
        }catch(IOException e){
            e.printStackTrace();
        }


        return cert;

    }



    private static void addEntityExtensions(X509v3CertificateBuilder certGen, PublicKey entityKey, PrivateKey caKey, X509Certificate caCert) {
        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                    false, utils.createAuthorityKeyIdentifier(caCert));

            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                    false, utils.createSubjectKeyIdentifier(entityKey));

            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                    true, new BasicConstraints(false));
            //a key usage extension that makes it suitable for use with SSL/TLS
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                    true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        } catch (CertificateEncodingException | CertIOException e) {
            e.printStackTrace();
        }

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


        long year = 360 * 24 * 60 * 60 * 1000;
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + year);


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
        PemObject key =  new PemObject("PRIVATE KEY", privKey.getEncoded());
        PemWriter wr = new PemWriter(new FileWriter(keyfile,false));
        wr.writeObject(key);
        wr.close();
    }

    private static void saveCertificate(String certfile, Certificate cert) throws IOException{
        PemObject key = null;
        try {
            key = new PemObject("CERTIFICATE", cert.getEncoded());
            PemWriter wr = new PemWriter(new FileWriter(certfile,false));
            wr.writeObject(key);
            wr.close();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

    }

    //TODO: request Certificate from CA
    public static X509Certificate certificateRequest(String subjectString, String p10){


        return null;
    }


    /**
     * Check ocsp boolean.
     *
     * @param cert the cert to check
     * @return the boolean, if cert is not valid, return true.
     */
    public static boolean checkOCSP(Certificate cert) {
        //TODO: check ocsp online
        //TODO: OCSP (http request ==> server, and get response)


        return false;
    }


    /**
     * Certificate verity boolean.
     *
     * @param cert the cert to check
     * @return the boolean, if cert is varified
     */
    public static boolean certificateVerify(X509Certificate cert){

        //verify
        try {
            cert.checkValidity(new Date()); // 有效期验证
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace(); //TODO: 用log记录
            return false;
        }

        //TODO: 证书签名验证; 证书信任链验证、密钥用法验证
        try {

                CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
                List<? extends Certificate>  certChain = getCertChain(cert);
               if (certChain==null) {
                   return false;
                }
               if (certChain.size() > 1) {    // not self-signed
                   CollectionCertStoreParameters params = new CollectionCertStoreParameters(certChain);

                   Certificate rootCert = certChain.get(certChain.size() - 1);
                   certChain.remove(rootCert);
                   CertPath certPath = fact.generateCertPath(certChain); //the path does not include the trust anchor
                    //CertPathValidator implementation uses the CertStore to look up any CRLs or certificates it might need
                   CertStore store = CertStore.getInstance("Collection", params, "BC");
                   //Set of TrustAnchor objects containing the self-signed root certificate that validates the intermediate certificate in the path
                   Set trust = Collections.singleton(new TrustAnchor((X509Certificate) rootCert, null));

                   // perform validation：
                   CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");

                   PKIXParameters param = new PKIXParameters(trust);
                   //param.addCertPathChecker(); // PathChecker: revocation checking
                   param.addCertStore(store);
                   param.setDate(new Date());
                   param.setRevocationEnabled(false);//tell the CertPathValidator implementation not to expect to use CRLs, as some other revocation mechanism has been enabled
                   try {
                       CertPathValidatorResult result = validator.validate(certPath, param);
                   }catch(Exception ee){
                       ee.printStackTrace();
                       return false;
                   }
               }
        }catch(Exception e){
                e.printStackTrace();
                return false;
        }



        if (checkCRL(cert)){
            return false;
        }

        if (checkOCSP(cert)){
            return false;
        }

        return true;
    }

    private static CertPath buildCertPath(X509Certificate endCert, X509Certificate rootCert){

        X509CertSelector endConstraints = new X509CertSelector();

        endConstraints.setSerialNumber(endCert.getSerialNumber());
        try {
            endConstraints.setIssuer(endCert.getIssuerX500Principal().getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        CollectionCertStoreParameters params = new CollectionCertStoreParameters( certlist);
        try {
            CertStore store = CertStore.getInstance( "Collection", params, BC);

            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", BC);

            PKIXBuilderParameters buildParams = new PKIXBuilderParameters( Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);

            buildParams.addCertStore(store);
            buildParams.setDate(new Date());

            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
            CertPath                  path = result.getCertPath();
            return path;
        } catch (InvalidAlgorithmParameterException | CertPathBuilderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static List<Certificate> getCertChain(Certificate cert){

        List list = new ArrayList();

        Certificate c = cert;
        while(true) {

            Certificate issuerCert = getIssuerCert(c);
            if (issuerCert == null) {
                return null; // something wrong
            }
            list.add(c);
            if (issuerCert == cert) {
                // self signed
                return list;
            } else {

                list.add(issuerCert);
                c = issuerCert;
            }
        }

    }

    private static Certificate getIssuerCert(Certificate cert){

        X509CertificateHolder ch = null;
        try {
            ch = new X509CertificateHolder(cert.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
            return  null;
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
            return  null;
        }
        if(ch.getSubject().equals(ch.getIssuer())){
            // self signed certificate
            return cert;
        }

        X500Name issuer = ch.getIssuer();
        Certificate c= getCertificatebyX500Name(issuer);
        if(c==null){
            // TODO: can not find the issuer's certificate
            return null;
        }else {
            return c;
        }
    }

    private static Certificate getCertificatebyX500Name(X500Name subject){

        // certificate store

        return null;
    }

    public static Certificate readPEMCert(String certfile)
            throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
        PemObject po = new PemReader(new FileReader(certfile)).readPemObject();
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(po.getContent()));
        certlist.add(cert);// save to list
        return cert;
    }

    //TODO: update CRL daily (by a new thread)
    public static  Collection<? extends CRL> readBASE64CRL(String crlname)
            throws Exception
    {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
        byte[] contents = getBytesFromFile(crlname);

        byte[] codes = Base64.decode(contents);

        Collection<? extends CRL> crls = cf.generateCRLs(new ByteArrayInputStream(codes));
        crllist.addAll(crls);// add to crllist for further search
        return crls;
    }

    private static byte[] getBytesFromFile(String filename) throws IOException {
        FileInputStream fis=new FileInputStream(filename);
        ByteArrayOutputStream baos=new ByteArrayOutputStream();
        int thebyte=0;
        while((thebyte=fis.read())!=-1)
        {
            baos.write(thebyte);
        }
        fis.close();
        byte[] contents=baos.toByteArray();
        baos.close();
        return contents;
    }

    public static List<? extends Certificate> readPEMCertPath(String certpathfile)
    {
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509", BC);
        } catch (NoSuchProviderException | CertificateException e) {
            e.printStackTrace();
        }
        try {
            byte[] contents = getBytesFromFile(certpathfile);
            CertPath path= cf.generateCertPath(new ByteArrayInputStream(contents));
            List certs = path.getCertificates();
            Iterator it = path.getCertificates().iterator();
            while (it.hasNext())
            {
                certlist.add((X509Certificate)it.next());// save to list
            }


            return certs;
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
       return null;

    }

    /**
     * Check crl boolean.
     *
     * @param cert the cert to check
     * @return the boolean, if cert is revoked, return true
     */
    public static boolean checkCRL(Certificate cert){

        //TODO: get CRL online

        //CRL
        if (crllist!=null){
            for (Iterator it = crllist.iterator(); it.hasNext();) {

                CRL s = (CRL) it.next();
                boolean result = s.isRevoked(cert);
                if(result){
                    return true; // found out that this cert is revoked
                }

            }
        }

        return false;

    }

}
