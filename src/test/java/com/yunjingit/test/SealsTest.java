package com.yunjingit.test;


import com.yunjingit.asn1.SESESPictrueInfo;
import com.yunjingit.asn1.SESSignature;
import com.yunjingit.asn1.SESeal;
import com.yunjingit.utils.Certifications;
import com.yunjingit.utils.PDFUtil;
import com.yunjingit.utils.Seals;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.junit.Test;
import org.junit.Before; 
import org.junit.After;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.util.Calendar;
import java.util.Date;

/** 
* Seals Tester. 
* 
* @author <Authors name> 
* @since <pre>十二月 24, 2018</pre> 
* @version 1.0 
*/ 
public class SealsTest { 

@Before
public void before() throws Exception {
    String issuerString = "CN=root,OU=单位,O=组织";
    Certificate rootcert = Certifications.generateV3CertificateSM2(issuerString,"sm2_root.pem",null,null);
    PrivateKey rootkey = Certifications.readPrivkey("sm2_root.pem");

    Certificate user1cert = Certifications.generateV3CertificateSM2("CN=user1,OU=单位,O=组织","sm2_usr1.pem",(X509Certificate) rootcert,rootkey);
    Certificate user2cert = Certifications.generateV3CertificateSM2("CN=user2,OU=单位,O=组织","sm2_usr2.pem",(X509Certificate) rootcert,rootkey);
    Certificate user3cert = Certifications.generateV3CertificateSM2("CN=user3,OU=单位,O=组织","sm2_usr3.pem",(X509Certificate) rootcert,rootkey);
    Certificate makercert = Certifications.generateV3CertificateSM2("CN=maker,OU=单位,O=组织","sm2_maker.pem",(X509Certificate) rootcert,rootkey);
} 

@After
public void after() throws Exception { 
} 

/** 
* 
* Method: esSignatureSign(byte[] contents, SESeal stamp, Certificate signercert, String propertyInfo, ECPrivateKeyParameters ecPriv)
* 
*/ 
@Test
public void testEsSignatureSign() throws Exception {

    String filename = "/pdf/rfc2560--OCSP.pdf";
    String filepath = this.getClass().getResource(filename).getFile();
    byte[] contents = PDFUtil.getBytesFromFile(filepath);

    SESeal stampFromFile = Seals.importSESeal("stamp.pem");
    if(stampFromFile == null){
        assert false;
    }
    String propertyInfo = "contents:all";
    Certificate rootcert = Certifications.readPEMCert("sm2_root.cer");
    Certificate usr1_cert = Certifications.readPEMCert("sm2_usr1.cer");
    Certificate usr2_cert = Certifications.readPEMCert("sm2_usr2.cer");
    Certificate usr3_cert = Certifications.readPEMCert("sm2_usr3.cer");
    Certificate maker_cert = Certifications.readPEMCert("sm2_maker.cer");

    AsymmetricKeyParameter usr2_key = Certifications.readPrivkeyToBC("sm2_usr2.pem");
    if(usr2_key instanceof ECPrivateKeyParameters){
        SESSignature sig = Seals.esSignatureSign(contents,stampFromFile,usr2_cert,propertyInfo,(ECPrivateKeyParameters)usr2_key);
        if(sig == null){
            assert false;
        }else{
            System.out.println(bytesToHex(sig.getEncoded()));
            boolean result = Seals.exportSESSignature(sig,"sig.pem");
            if(result){
                SESSignature sigFromFile = Seals.importSESSignature("sig.pem");
                if(sigFromFile == null){
                    assert false;
                }
                byte[] data1 = sig.getEncoded();
                byte[] data2 = sigFromFile.getEncoded();
                int result_i = Arrays.compareUnsigned(data1,data2);
                if(result_i == 0){
                    assert true;
                }
            }else{
                assert false;
            }
        }
    }else{

        assert false;
    }



} 

/** 
* 
* Method: processContents(byte[] input, String propertyInfo) 
* 
*/ 
@Test
public void testProcessContents() throws Exception { 
//TODO: Test goes here... 
} 

/** 
* 
* Method: esSignatureVerity(byte[] contents, byte[] sealsignature)
* 
*/ 
@Test
public void testEsSignatureVerity() throws Exception {
//TODO: Test goes here... 
} 

/** 
* 
* Method: esealVerify(byte[]  stampdata, Date refDate)
* 
*/ 
@Test
public void testEsealVerify() throws Exception {

    Certificate rootcert = Certifications.readPEMCert("sm2_root.cer");
    Certificate usr1_cert = Certifications.readPEMCert("sm2_usr1.cer");
    Certificate usr2_cert = Certifications.readPEMCert("sm2_usr2.cer");
    Certificate usr3_cert = Certifications.readPEMCert("sm2_usr3.cer");
    Certificate maker_cert = Certifications.readPEMCert("sm2_maker.cer");

    SESeal stampFromFile = Seals.importSESeal("stamp.pem");
    if(stampFromFile == null){
        assert false;
    }

    byte[] data = stampFromFile.getEncoded();
    int result = Seals.esealVerify(data,null);
    if(result == 1){
        assert true;
    }else{
        System.out.printf("result = %d\n",result);
        assert false;
    }

} 

/** 
* 
* Method: esealGenerate(String esID, int type, String name, org.bouncycastle.asn1.x509.Certificate[] certlist, Date start, Date end, SESESPictrueInfo pic, org.bouncycastle.asn1.x509.Certificate makercert, ECPrivateKeyParameters ecPriv) 
* 
*/ 
@Test
public void testEsealGenerate() throws Exception {
    String esID="10001000";
    int type = 1;
    String name = "test stamp";

    Certificate rootcert = Certifications.readPEMCert("sm2_root.cer");
    Certificate usr1_cert = Certifications.readPEMCert("sm2_usr1.cer");
    Certificate usr2_cert = Certifications.readPEMCert("sm2_usr2.cer");
    Certificate usr3_cert = Certifications.readPEMCert("sm2_usr3.cer");
    Certificate maker_cert = Certifications.readPEMCert("sm2_maker.cer");

    org.bouncycastle.asn1.x509.Certificate[] certlist = new org.bouncycastle.asn1.x509.Certificate[3];
    certlist[0] = Certifications.convertFromCert((X509Certificate) usr1_cert);
    certlist[1] = Certifications.convertFromCert((X509Certificate) usr2_cert);
    certlist[2] = Certifications.convertFromCert((X509Certificate) usr3_cert);
    Date start = new Date();
    Calendar cal = Calendar.getInstance();
    cal.setTime(start);
    cal.add(Calendar.YEAR, 1);
    Date end = cal.getTime();

    String filename = "/img/u3746436225744464902fm214.jpg";
    String filepath = this.getClass().getResource(filename).getFile();
    SESESPictrueInfo pic = Seals.pictrueInfoBuilder(filepath, 10,15);
    org.bouncycastle.asn1.x509.Certificate makercert = Certifications.convertFromCert((X509Certificate) maker_cert);
    AsymmetricKeyParameter ecPriv = Certifications.readPrivkeyToBC("sm2_maker.pem");
    if(ecPriv instanceof ECPrivateKeyParameters){
        SESeal stamp = Seals.esealGenerate(esID,type,name,certlist,start,end,pic,makercert,(ECPrivateKeyParameters) ecPriv);
        if(stamp!=null){
            System.out.println(bytesToHex(stamp.getEncoded()));
            boolean result = Seals.exportSESeal(stamp,"stamp.pem");
            if(result){
                SESeal stampFromFile = Seals.importSESeal("stamp.pem");
                if(stampFromFile == null){
                    assert false;
                }
                byte[] data1 = stamp.getEncoded();
                byte[] data2 = stampFromFile.getEncoded();
                int result_i = Arrays.compareUnsigned(data1,data2);
                if(result_i == 0){
                    assert true;
                }
            }else{
                assert false;
            }

        }else{
            assert false;
        }
    }else{

        assert false;
    }


}


/**  * 字节数组转16进制
 * * @param bytes 需要转换的byte数组
 * * @return  转换后的Hex字符串
 * */
public static String bytesToHex(byte[] bytes) {
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < bytes.length; i++) {
        String hex = Integer.toHexString(bytes[i] & 0xFF);
        if (hex.length() < 2) {
            sb.append(0);
        }
        sb.append(hex);
    }
    return sb.toString();
}


/** 
* 
* Method: getEcPublicKeyParameters(Certificate cert) 
* 
*/ 
@Test
public void testGetEcPublicKeyParameters() throws Exception {

    Certificate rootcert = Certifications.readPEMCert("sm2_root.cer");
    ECPublicKeyParameters param = Seals.getEcPublicKeyParameters(rootcert);
    if(param!=null){
        System.out.println(param.toString());
        assert  true;
    }else{
        assert false;
    }
} 

} 
