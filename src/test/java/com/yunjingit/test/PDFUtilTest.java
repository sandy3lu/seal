package com.yunjingit.test;


import com.itextpdf.text.BadElementException;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.yunjingit.asn1.SESSignature;
import com.yunjingit.utils.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.symmetric.SM4;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.junit.Before; 
import org.junit.After;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dsig.DigestMethod;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;

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

        byte[] con = PDFUtil.getBytesFromFile(dest);
        try {
            byte[] data = PDFUtil.getSignatures(con);
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
        byte[] contents = PDFUtil.getBytesFromFile(dest)    ;
        try {
            PDFUtil.getSignatures(contents, false);

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

    @Test
    public void testPDFSignRSA(){

        String filename = "/pdf/rfc2560--OCSP.pdf";
        String filepath = this.getClass().getResource(filename).getFile();
        String dest = "rfc2560--OCSP--rsa-signed.pdf";
        String imagefile = this.getClass().getResource("/img/100sh.png").getFile();
        File f = new File("rsa-sign.pfx");

        KeyStore pkcs12 = null;
        try {
            pkcs12 = KeyStore.getInstance("PKCS12", "BC");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        if(!f.exists()) {
            Certifications.generateV3Certificate("CN=root,OU=yunjing,O=research", "rsa-sign.pem", "rsa-sign-cert.cer");

        }
        try {
            pkcs12.load(new FileInputStream("rsa-sign.pfx"), "123321".toCharArray());
            PrivateKey pk = (PrivateKey)pkcs12.getKey("privateKey", null);
            Certificate[] pubCerts = pkcs12.getCertificateChain("privateKey");

            PdfReader reader = new PdfReader(filepath);
            FileOutputStream os = new FileOutputStream(dest);

            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);

            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason("test rsa");
            appearance.setLocation(" pdf util test");
            appearance.setVisibleSignature(new Rectangle(200, 200, 300, 300), 1, "sigRSA");

            Image image = Image.getInstance(imagefile);
            appearance.setSignatureGraphic(image);
            appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

            PDFUtil.signRSA(pk, DigestAlgorithms.SHA1,appearance,pubCerts, MakeSignature.CryptoStandard.CMS);
            assert true;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (BadElementException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            e.printStackTrace();
        }


    }


    @Test
    public void testPDFSignSM2(){

        String filename = "/pdf/rfc2560--OCSP.pdf";
        String filepath = this.getClass().getResource(filename).getFile();
        String dest = "rfc2560--OCSP--SM2-signed.pdf";
        String imagefile = this.getClass().getResource("/img/100sh.png").getFile();
        File f = new File("sm2-sign.pfx");

        KeyStore pkcs12 = null;
        try {
            pkcs12 = KeyStore.getInstance("PKCS12", "BC");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        if(!f.exists()) {
            Certifications.generateV3CertificateSM2("CN=root,OU=yunjing,O=research", "sm2-sign.pem", null,null);

        }
        try {
            pkcs12.load(new FileInputStream("sm2-sign.pfx"), "123321".toCharArray());
            PrivateKey pk = (PrivateKey)pkcs12.getKey("privateKey", null);
            Certificate[] pubCerts = pkcs12.getCertificateChain("privateKey");

            PdfReader reader = new PdfReader(filepath);
            FileOutputStream os = new FileOutputStream(dest);

            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);

            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason("test sm2");
            appearance.setLocation(" pdf util test");
            appearance.setVisibleSignature(new Rectangle(200, 200, 300, 300), 1, "sigRSA");

            Image image = Image.getInstance(imagefile);
            appearance.setSignatureGraphic(image);
            appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
            appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

            PDFUtil.signSM2(pk, appearance,pubCerts, MakeSignature.CryptoStandard.CMS);
            assert true;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (BadElementException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            e.printStackTrace();
        }


    }

    @Test
    public void testSM4(){
        String s = "0123456789abcdeffedcba9876543210";
        String plain = "0123456789abcdeffedcba9876543210";
        String cipher =  "681edf34d206965e86b3e94f536e4246";
        Key key = new SecretKeySpec(Hex.decode(s), "SM4");
        SM4Engine sm4Engine = new SM4Engine();
        KeyParameter keyParameter = new KeyParameter(key.getEncoded());
        sm4Engine.init(true,keyParameter);
        byte[] out = new byte[16];
        int len = sm4Engine.processBlock(Hex.decode(plain),0,out,0);
        System.out.println();
        if(ByteUtils.toHexString(out).equals(cipher)){
            sm4Engine.init(false,keyParameter);
            byte[] result = new byte[16];
            int len2 = sm4Engine.processBlock(out,0,result,0);
            System.out.println();
            if(ByteUtils.toHexString(result).equals(plain)){
                assert true;
            }else{
                assert false;
            }
        }else {
            assert false;
        }

    }

    @Test
    public void testAES128(){
        //128bit
        String s = "000102030405060708090a0b0c0d0e0f";
        String plain = "00112233445566778899aabbccddeeff";
        String cipher =  "69c4e0d86a7b0430d8cdb78070b4c55a";
        Key key = new SecretKeySpec(Hex.decode(s), "AES");
        AESEngine aesEngine = new AESEngine();
        KeyParameter keyParameter = new KeyParameter(key.getEncoded());
        aesEngine.init(true,keyParameter);
        byte[] out = new byte[16];
        int len = aesEngine.processBlock(Hex.decode(plain),0,out,0);
        System.out.println();
        if(ByteUtils.toHexString(out).equals(cipher)){
            aesEngine.init(false,keyParameter);
            byte[] result = new byte[16];
            int len2 = aesEngine.processBlock(out,0,result,0);
            System.out.println();
            if(ByteUtils.toHexString(result).equals(plain)){
                assert true;
            }else{
                assert false;
            }
        }else {
            assert false;
        }

    }

    @Test
    public void testAES192(){

        String s = "000102030405060708090a0b0c0d0e0f1011121314151617";
        String plain = "00112233445566778899aabbccddeeff";
        String cipher =  "dda97ca4864cdfe06eaf70a0ec0d7191";
        Key key = new SecretKeySpec(Hex.decode(s), "AES");
        AESEngine aesEngine = new AESEngine();
        KeyParameter keyParameter = new KeyParameter(key.getEncoded());
        aesEngine.init(true,keyParameter);
        byte[] out = new byte[16];
        int len = aesEngine.processBlock(Hex.decode(plain),0,out,0);
        System.out.println();
        if(ByteUtils.toHexString(out).equals(cipher)){
            aesEngine.init(false,keyParameter);
            byte[] result = new byte[16];
            int len2 = aesEngine.processBlock(out,0,result,0);
            System.out.println();
            if(ByteUtils.toHexString(result).equals(plain)){
                assert true;
            }else{
                assert false;
            }
        }else {
            assert false;
        }

    }

    @Test
    public void testSM2Enc(){
        byte[] m = Strings.toByteArray("encryption standard");
        KeyPair keyPair;
        ECKeyParameters ecKeyParameters=null;
        ECPublicKeyParameters param=null;
        try {
            keyPair = Keys.generateSM2KeyPair();

            ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
            ECCurve curve = new SM2P256V1Curve();
            BigInteger SM2_ECC_N = new BigInteger(
                    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
            BigInteger SM2_ECC_GX = new BigInteger(
                    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
            BigInteger SM2_ECC_GY = new BigInteger(
                    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
            ECPoint G_POINT = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
            ECDomainParameters ecDomainParameters = new ECDomainParameters(curve,G_POINT,SM2_ECC_N  );
            ecKeyParameters = new ECPrivateKeyParameters(ecPrivateKey.getS(),ecDomainParameters);


            BCECPublicKey localECPublicKey = (BCECPublicKey)keyPair.getPublic();
            ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                    localECParameterSpec.getG(), localECParameterSpec.getN());
            param = new ECPublicKeyParameters(localECPublicKey.getQ(),localECDomainParameters);
        } catch (Exception e) {
            e.printStackTrace();
            assert false;
        }
        SM2Engine sm2Engine = new SM2Engine();

        ParametersWithRandom parametersWithRandom = new ParametersWithRandom(param);
        sm2Engine.init(true,parametersWithRandom);
        try {
            byte[] enc = sm2Engine.processBlock(m, 0, m.length);

            sm2Engine.init(false, ecKeyParameters);
            byte[] dec = sm2Engine.processBlock(enc, 0, enc.length);

            boolean result = Arrays.areEqual(m, dec);
            if(result){
                assert true;
            }else {
                assert false;
            }
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            assert false;
        }

    }
} 
