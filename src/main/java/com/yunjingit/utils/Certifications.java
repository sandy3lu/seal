package com.yunjingit.utils;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
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

    public static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
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

        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(notBefore);
        cal.add(Calendar.YEAR, 1);
        Date notAfter = cal.getTime();

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
        } catch (Exception e) {
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
        saveAsP12(keyfile, privKey, cert);
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

    public static X509Certificate generateV3CertificateSM2(String subjectString, String keyfile, X509Certificate rootcert, PrivateKey rootkey){
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


        X500Name subjectDn = new X500Name(subjectString);
        X500Name issueDn = subjectDn;

        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(notBefore);
        cal.add(Calendar.YEAR, 1);
        Date notAfter = cal.getTime();

        BigInteger serial = BigInteger.probablePrime(32, new Random());

        ContentSigner sigGen = null;
        try {
            if(rootcert == null) {
                sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider(BC).build(privKey);

            }else{
                sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider(BC).build(rootkey);
                String issuer = rootcert.getIssuerDN().getName();
                issueDn = new X500Name(issuer);
            }
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

        // extensions
        JcaX509ExtensionUtils utils = null;
        try {
            utils = new JcaX509ExtensionUtils();
            if(rootcert == null){
                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(true)); // is CA
                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                        false, utils.createSubjectKeyIdentifier(pubKey));
                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature ));

            }else{
                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(false));
                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                        false, utils.createAuthorityKeyIdentifier(rootcert));

                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier,
                        false, utils.createSubjectKeyIdentifier(pubKey));
                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature ));
            }
        } catch (NoSuchAlgorithmException | CertIOException | CertificateEncodingException e) {
            e.printStackTrace();
        }

        X509Certificate cert = null;
        try {
            cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));
            cert.checkValidity(new Date());
            if(rootcert == null){
                cert.verify(pubKey);
            }else{
                PublicKey publickey = rootcert.getPublicKey();
                cert.verify(publickey);
            }

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();

        }
        try{
            savePrivkey( keyfile, privKey);
            String certfile = keyfile.replace("pem","cer");
            saveCertificate( certfile, cert);
        }catch(IOException e){
            e.printStackTrace();
        }

        saveAsP12(keyfile, privKey, cert);
        return cert;

    }

    private static void saveAsP12(String keyfile, PrivateKey privKey, X509Certificate cert) {
        Certificate[] chain = new Certificate[1];
        chain[0] = cert;
        KeyStore store = null;
        try {
            store = KeyStore.getInstance("PKCS12", "BC");
            store.load(null, null);
            store.setKeyEntry("privateKey", privKey, null, chain);
            String pfxfile = keyfile.replace(".pem", ".pfx");
            char[] passwd = "123321".toCharArray();
            store.store(new FileOutputStream(pfxfile), passwd);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void savePrivkey(String keyfile, PrivateKey privKey) throws IOException{
        PemObject key =  new PemObject("PRIVATE KEY", privKey.getEncoded());
        PemWriter wr = new PemWriter(new FileWriter(keyfile,false));
        wr.writeObject(key);
        wr.close();
    }

    public static PrivateKey  readPrivkey(String keyfile) throws IOException{

        PemReader rd = new PemReader(new FileReader(keyfile));
        PemObject keyobj = rd.readPemObject();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyobj.getContent()));

        PrivateKey     key = BouncyCastleProvider.getPrivateKey(privateKeyInfo);

        return key;
    }

    public static AsymmetricKeyParameter  readPrivkeyToBC(String keyfile) throws IOException{

        PemReader rd = new PemReader(new FileReader(keyfile));
        PemObject keyobj = rd.readPemObject();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyobj.getContent()));
        AsymmetricKeyParameter key = PrivateKeyFactory.createKey(privateKeyInfo);

        return key;
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


    public static boolean certificateVerify(X509Certificate cert){
        return certificateVerify( cert, new Date(), true);
    }

    /**
     * Certificate verity boolean.
     *
     * @param cert the cert to check
     * @return the boolean, if cert is varified
     */
    public static boolean certificateVerify(X509Certificate cert, Date refDate, boolean checkOCSP){


        //verify
        try {
            if(refDate == null){
                cert.checkValidity(new Date()); //
            }else{
                cert.checkValidity(refDate); // valid date
            }

        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace(); //TODO: 用log记录
            return false;
        }

        //TODO: signature; cert chain;  key usage
        try {

                CertificateFactory fact = CertificateFactory.getInstance("X.509", Certifications.BC);
                List<? extends Certificate>  certChain = getCertChain(cert);
               if (certChain==null) {
                   return false;
                }
               if (certChain.size() > 1) {    // not self-signed
                   X509CertificateHolder[] holders = new X509CertificateHolder[certChain.size()];
                   for(int i=0; i<certChain.size();i++){
                       X509Certificate c = (X509Certificate)certChain.get(i);
                       X509CertificateHolder holder = new X509CertificateHolder(c.getEncoded());
                       holders[i] = holder;
                   }
                   //org.bouncycastle.cert.path.CertPath path = new org.bouncycastle.cert.path.CertPath(holders);
                   //X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                   //CertPathValidationResult result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation()});
                   X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                   verifier = new TokenX509ContentVerifierProviderBuilder();
                   certPathVaild(holders,new ParentCertIssuedValidation(verifier));
                   certPathVaild(holders,new BasicConstraintsValidation());
                   //certPathVaild(holders,new KeyUsageValidation());

               }
        }catch(Exception e){
                e.printStackTrace();
                return false;
        }



        if (checkCRL(cert, refDate)){
            return false;
        }

        if(checkOCSP) {
            if (checkOCSP(cert)) {
                return false;
            }
        }
        return true;
    }


    private static void certPathVaild(X509CertificateHolder[] certificates, CertPathValidation ruleSet) throws CertPathValidationException {

        Set criticalExtensions = new HashSet();

        for (int i = 0; i != certificates.length; i++)
        {
            criticalExtensions.addAll(certificates[i].getCriticalExtensionOIDs());
        }

        CertPathValidationContext context = new CertPathValidationContext(criticalExtensions);
        for (int j = certificates.length - 1; j >= 0; j--)
        {
            try
            {
                context.setIsEndEntity(j == 0);
                ruleSet.validate(context, certificates[j]);
            }
            catch (CertPathValidationException e)
            {
                throw e;
            }
        }
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
        list.add(c);
        while(true) {

            Certificate issuerCert = getIssuerCert(c);
            if (issuerCert == null) {
                return null; // something wrong
            }

            if (issuerCert == c) {
                // self signed
                return list;
            } else {

                list.add(issuerCert);
                c = issuerCert;
            }
        }

    }

    private static Certificate getIssuerCert(Certificate cert){

        Principal issuerDN = ((X509Certificate)cert).getIssuerDN();
        if(issuerDN!=null){
            for(Certificate c : certlist){
                Principal principal =  ((X509Certificate)c).getSubjectDN();
                if (principal.equals(issuerDN)){
                    return c;
                }

            }
            return null;
        }else{
            issuerDN = ((X509Certificate)cert).getIssuerX500Principal();
            for(Certificate c : certlist){
                Principal principal =  ((X509Certificate)c).getSubjectX500Principal();
                if (principal.equals(issuerDN)){
                    return c;
                }

            }
            return null;
        }


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

    public static org.bouncycastle.asn1.x509.Certificate convertFromCert(X509Certificate cert){
        try {
            byte[] data = cert.getEncoded();
            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(data));
            ASN1Sequence seq = ASN1Sequence.getInstance(aIn.readObject());
            org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(seq);
            return c;
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    //TODO: update CRL daily (by a new thread)
    public static  Collection<? extends CRL> readBASE64CRL(String crlname)
            throws Exception
    {

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
        byte[] contents = PDFUtil.getBytesFromFile(crlname);

        byte[] codes = Base64.decode(contents);

        Collection<? extends CRL> crls = cf.generateCRLs(new ByteArrayInputStream(codes));
        crllist.addAll(crls);// add to crllist for further search
        return crls;
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
            byte[] contents = PDFUtil.getBytesFromFile(certpathfile);
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
    public static boolean checkCRL(Certificate cert, Date refDate){

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
