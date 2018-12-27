package com.yunjingit.utils;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import com.yunjingit.asn1.SESESPictrueInfo;
import com.yunjingit.asn1.SESSignature;

import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.HashMap;


public class PDFUtil {
    static String version = "1.0";

    public static byte[] readPDF(String filename){
        File tmpFile = new File(filename);
        if (!filename.toLowerCase().endsWith(".pdf") && !tmpFile.isFile()) {
           return null;
        }else {
            if (!tmpFile.canRead()){
                return null; //can not read
            }
            //TODO: read pdf contents
            return null;
        }

    }

    public static byte[] getBytesFromFile(String filename) throws IOException {
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


    public static void sign(String src, String dest, SESSignature sesSignature)  throws IOException, DocumentException {

        PdfReader reader = new PdfReader(src);
        File destfile = new File(dest);
        if(!destfile.exists()){
            destfile.createNewFile();
        }
        FileOutputStream os = new FileOutputStream(dest);
        //false : only sign once
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);

        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("guomi eseal");
        appearance.setLocation("yunjing");

        //图章图片，这个image是itext包的image
        SESESPictrueInfo pic = sesSignature.getToSign().getEseal().getEsealInfo().getPicture();
        BigInteger height = pic.getHeight().getValue();
        BigInteger width = pic.getWidth().getValue();
        byte[] imgdata = pic.getData().getOctets();
        Image image = Image.getInstance(imgdata);
        appearance.setSignatureGraphic(image);

        float left_x = 200;
        float left_y = 200;
        float right_x = left_x + width.floatValue();
        float right_y = left_y + height.floatValue();

        // set position
        appearance.setVisibleSignature(new Rectangle(left_x, left_y, right_x, right_y), 1, "sig1");

        appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
        //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason(appearance.getReason());
        dic.setLocation(appearance.getLocation());
        dic.setContact(appearance.getContact());
        dic.setDate(new PdfDate(appearance.getSignDate()));
        appearance.setCryptoDictionary(dic);

        int contentEstimated = 1500000;
        HashMap<PdfName,Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
        appearance.preClose(exc);


        PdfDictionary dic2 = new PdfDictionary();
        byte[] paddedSig = sesSignature.getEncoded();
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        appearance.close(dic2);

        //ExternalDigest digest = new BouncyCastleDigest();
        //ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, null);
        //MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

}
