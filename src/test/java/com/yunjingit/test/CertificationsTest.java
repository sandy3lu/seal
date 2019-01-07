package com.yunjingit.test;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.Before; 
import org.junit.After;

import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

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

} 
