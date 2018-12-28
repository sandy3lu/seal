package com.yunjingit.test;


import com.yunjingit.asn1.SESSignature;
import com.yunjingit.utils.OtherUtil;
import com.yunjingit.utils.PDFUtil;
import com.yunjingit.utils.Seals;
import org.bouncycastle.util.Arrays;
import org.junit.Test;
import org.junit.Before; 
import org.junit.After; 

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
    String dest = "g://rfc2560--OCSP--signed.pdf";

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
        String filename = "/pdf/rfc2560--OCSP.pdf";

        String dest = "g://rfc2560--OCSP--signed.pdf";

        SESSignature sigFromFile = Seals.importSESSignature("sig.pem");
        if(sigFromFile == null){
            assert false;
        }
        try {
            byte[] data = PDFUtil.getSignatures(dest);
            byte[] sig = sigFromFile.getEncoded();
            int result_i = Arrays.compareUnsigned(data,sig);
            if (result_i == 0){
                assert true;
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



} 
