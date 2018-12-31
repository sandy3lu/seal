package com.yunjingit.test;


import com.yunjingit.asn1.SESSignature;
import com.yunjingit.utils.Certifications;
import com.yunjingit.utils.OtherUtil;
import com.yunjingit.utils.PDFUtil;
import com.yunjingit.utils.Seals;
import org.bouncycastle.util.Arrays;
import org.junit.Test;
import org.junit.Before; 
import org.junit.After;

import java.io.IOException;
import java.security.cert.Certificate;

/** 
* PDFUtil Tester. 
* 
* @author <Authors name> 
* @since <pre>ʮ���� 27, 2018</pre> 
* @version 1.0 
*/ 
public class PDFUtilTest { 

@Before
public void before() throws Exception {

    Certificate rootcert = Certifications.readPEMCert("sm2_root.cer");
    Certificate usr1_cert = Certifications.readPEMCert("sm2_usr1.cer");
    Certificate usr2_cert = Certifications.readPEMCert("sm2_usr2.cer");
    Certificate usr3_cert = Certifications.readPEMCert("sm2_usr3.cer");
    Certificate maker_cert = Certifications.readPEMCert("sm2_maker.cer");
} 

@After
public void after() throws Exception { 
} 

/** 
* 
* Method: readPDF(String filename) 
* 
*/ 
@Test
public void testReadPDF() throws Exception { 

    String dest = "g://test--signed.pdf";

    try {
        byte[] data = PDFUtil.readPDF(dest);

        assert true;

    }catch (Exception e){
        System.out.println(e.getMessage());
        assert false;
    }
} 

/** 
* 
* Method: getBytesFromFile(String filename) 
* 
*/ 
@Test
public void testGetBytesFromFile() throws Exception { 
//TODO: Test goes here... 
} 

/** 
* 
* Method: sign(String src, String dest, SESSignature sesSignature) 
* 
*/ 
@Test
public void testSign() throws Exception {
    String filename = "/pdf/rfc2560--OCSP.pdf";
    String filepath = this.getClass().getResource(filename).getFile();
    String dest = "rfc2560--OCSP--signed.pdf";

    SESSignature sigFromFile = Seals.importSESSignature("sig.pem");
    if(sigFromFile == null){
        assert false;
    }
    try {
        PDFUtil.sign(filepath, dest, sigFromFile);
        assert true;
    }catch (Exception e){
        System.out.println(e.getMessage());
        assert false;
    }
}

    /**
     *
     * Method: byte[] getSignatures(String src)
     *
     */
    @Test
    public void testGetSignatures() throws Exception {
        String dest = "rfc2560--OCSP--signed.pdf";

        SESSignature sigFromFile = Seals.importSESSignature("sig.pem");
        if(sigFromFile == null){
            assert false;
        }
        try {
            byte[] data = PDFUtil.getSignatures(dest);
            byte[] sig = sigFromFile.getEncoded();
            int result_i = Arrays.compareUnsigned(data,sig);
            if (result_i == 0){

                byte[] des = new byte[0];
                try {
                    des = PDFUtil.getBytesFromFile(dest);
                } catch (IOException e) {
                    e.printStackTrace();
                    assert false;
                }
                byte[] dest_tosign = PDFUtil.getPDFcontentForSign(des);
                boolean result = Seals.esSignatureVerity(dest_tosign,sig);
                if(result) {
                    assert true;
                }else {
                    assert false;
                }
            }else {
                assert false;
            }
        }catch (Exception e){
            System.out.println(e.getMessage());
            assert false;
        }
    }

    @Test
    public void testGetSignatures2() throws Exception {
        String dest = "g://test--signed.pdf";

        try {
            PDFUtil.getSignatures(dest, false);

            assert true;

        } catch (Exception e) {
            System.out.println(e.getMessage());
            assert false;
        }
    }

    @Test
    public void testGetPDFcontentForSign(){

        String filename = "/pdf/rfc2560--OCSP.pdf";
        String filepath = this.getClass().getResource(filename).getFile();
        String dest = "rfc2560--OCSP--signed.pdf";

        byte[] ori = new byte[]{0x61,0x72,0x74,0x78,0x72,0x65,0x66,0x0a,0x35,0x32,0x34,0x35,0x32, 0x0a,0x25,0x25,0x45,0x4f,0x46,0x0a};
        byte[] ori_tosign2 = PDFUtil.getPDFcontentForSign(ori);
        int result_i = Arrays.compareUnsigned(ori,ori_tosign2);
        if(result_i != 0){assert false;}

        try {
            ori = PDFUtil.getBytesFromFile(filepath);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] ori_tosign = PDFUtil.getPDFcontentForSign(ori);

        byte[] des = new byte[0];
        try {
            des = PDFUtil.getBytesFromFile(dest);
        } catch (IOException e) {
            e.printStackTrace();
            assert false;
        }
        byte[] dest_tosign = PDFUtil.getPDFcontentForSign(des);

        int result = Arrays.compareUnsigned(ori_tosign,dest_tosign);
        if(result == 0 ){
            result = Arrays.compareUnsigned(ori_tosign,ori);

            if(result == 0){
                assert true;
            }else {
                assert false;
            }
        }else{
            assert false;
        }
    }
} 
