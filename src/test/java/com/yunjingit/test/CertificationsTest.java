package com.yunjingit.test;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.Before; 
import org.junit.After;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

/** 
* Certifications Tester. 
* 
* @author <Authors name> 
* @since <pre>Ê®¶þÔÂ 18, 2018</pre> 
* @version 1.0 
*/ 
public class CertificationsTest { 

@Before
public void before() throws Exception { 
} 

@After
public void after() throws Exception { 
} 

/** 
* 
* Method: generateV3Certificate(String issuerString, String keyfile) 
* 
*/ 
@Test
public void testGenerateV3Certificate() throws Exception { 

  Certificate cert= com.yunjingit.utils.Certifications.generateV3Certificate("CN=root,OU=yunjing,O=research", "rsa.pem", "rsa-cert.cer");
  if(cert !=null){
      System.out.println(cert.toString());
      assert(true);
  }else{
      assert (false);
  }
} 

/** 
* 
* Method: generateV3CertificateSM2(String issuerString, String keyfile) 
* 
*/ 
@Test
public void testGenerateV3CertificateSM2() throws Exception { 
//TODO: Test goes here... 
} 

/** 
* 
* Method: certificateVerify(X509Certificate cert)
* 
*/ 
@Test
public void testcertificateVerify() throws Exception {
//TODO: Test goes here... 
} 

/** 
* 
* Method: readPEMCert(String pemData) 
* 
*/ 
@Test
public void testReadPEMCert() throws Exception { 
    //RSA test
    String filepath = this.getClass().getResource("/cqcca/CQCCA.cer").getFile();
    System.out.println(filepath);
    try {
        Certificate x = com.yunjingit.utils.Certifications.readPEMCert(filepath);
        String dn = ((X509Certificate)x).getIssuerDN().getName();
        String principal =((X509Certificate)x).getIssuerX500Principal().toString();
        System.out.printf("%s  VS  %s \n" , dn, principal);
        System.out.println(x.toString());

    }catch(Exception e){
        e.printStackTrace();
        assert(false) ;

    }

    // SM2 test
     filepath = this.getClass().getResource("/cqcca/CQCCA_SM2.cer").getFile();

    try {
        Certificate x = com.yunjingit.utils.Certifications.readPEMCert(filepath);
        X509Certificate xx = (X509Certificate)  x;

        System.out.println(x.toString());
        assert(true) ;
    }catch(Exception e){
        e.printStackTrace();
        assert(false) ;

    }
}


/**
*
* Method: Collection<? extends CRL> readBASE64CRL(String pemData)
*
*/
@Test
public void testreadBASE64CRL() throws Exception {

    String filepath = this.getClass().getResource("/carl.crl").getFile();
    System.out.println(filepath);
    try {
        Collection<? extends CRL> crls = com.yunjingit.utils.Certifications.readBASE64CRL(filepath);
        for(CRL x : crls){
            System.out.println(x.toString());
        }
        assert(true) ;
    }catch(Exception e){
        e.printStackTrace();
        assert(false) ;

    }

}

    /**
* 
* Method: readPEMCertPath(String pemData) 
* 
*/ 
@Test
public void testReadPEMCertPath() throws Exception { 
//TODO: Test goes here...
    byte[] data = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

    // java.util.Base64.getUrlEncoder().encode();
} 


/** 
* 
* Method: addEntityExtensions(X509v3CertificateBuilder certGen, PublicKey entityKey, PrivateKey caKey, X509Certificate caCert) 
* 
*/ 
@Test
public void testAddEntityExtensions() throws Exception { 
//TODO: Test goes here... 
/* 
try { 
   Method method = Certifications.getClass().getMethod("addEntityExtensions", X509v3CertificateBuilder.class, PublicKey.class, PrivateKey.class, X509Certificate.class); 
   method.setAccessible(true); 
   method.invoke(<Object>, <Parameters>); 
} catch(NoSuchMethodException e) { 
} catch(IllegalAccessException e) { 
} catch(InvocationTargetException e) { 
} 
*/ 
} 

/** 
* 
* Method: savePrivkey(String keyfile, PrivateKey privKey) 
* 
*/ 
@Test
public void testSavePrivkey() throws Exception { 
//TODO: Test goes here... 
/* 
try { 
   Method method = Certifications.getClass().getMethod("savePrivkey", String.class, PrivateKey.class); 
   method.setAccessible(true); 
   method.invoke(<Object>, <Parameters>); 
} catch(NoSuchMethodException e) { 
} catch(IllegalAccessException e) { 
} catch(InvocationTargetException e) { 
} 
*/ 
}

@Test
public void testP7B() throws Exception{

    String p7b ="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";
    byte[] content = Base64.decode(p7b);
    FileOutputStream os = new FileOutputStream("p7b.asn");
    os.write(content);
    os.close();
    CMSSignedData cmsSignedData = new CMSSignedData(content);
    CollectionStore<X509CertificateHolder> certStore =
            (CollectionStore<X509CertificateHolder>) cmsSignedData.getCertificates();
    Iterator iterator = certStore.iterator();
    ArrayList<org.bouncycastle.asn1.x509.Certificate> certificates = new ArrayList<>();
    while (iterator.hasNext()) {
        X509CertificateHolder certificateHolder = (X509CertificateHolder) iterator.next();
        org.bouncycastle.asn1.x509.Certificate certificate = certificateHolder.toASN1Structure();
        certificates.add(certificate);
    }

    assert true;

}

} 
