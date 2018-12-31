package com.yunjingit.utils;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.PageSize;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.*;

import com.yunjingit.asn1.SESESPictrueInfo;
import com.yunjingit.asn1.SESSignature;

import java.io.*;
import java.math.BigInteger;

import java.security.GeneralSecurityException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;


public class PDFUtil {
    static String version = "1.0";
    static String SIGNATURE_NAME = "yunjing GuoMi";
    static int A4_WIDTH_MM = 210;
    static int A4_HEIGHT_MM = 297;
    static float scale_h = PageSize.A4.getHeight()/A4_HEIGHT_MM;
    static float scale_w = PageSize.A4.getWidth()/A4_WIDTH_MM;

    static  byte[] PDF_END = new byte[]{0x45, 0x4f,0x46, 0x0a};

    public static byte[] readPDF(String filename){
        File tmpFile = new File(filename);
        if (!filename.toLowerCase().endsWith(".pdf") && !tmpFile.isFile()) {
           return null;
        }else {
            if (!tmpFile.canRead()){
                return null; //can not read
            }

            try {
                PdfReader reader = new PdfReader(filename);
                reader.getPageSize(1);


                int num = reader.getNumberOfPages();
                byte[] data= reader.getPageContent(1);
                for(int i=2; i<=num;i++){
                    byte[] tmp = reader.getPageContent(i);
                    data = byteMerger(data,tmp);
                }
                return data;
            } catch (IOException e) {
                e.printStackTrace();
            }

            return null;
        }

    }

    public static byte[] getPDFcontentForSign(byte[] pdf){

        int index = ByteIndexOf(pdf,PDF_END);
        if(index>0){
            byte[] result = new byte[index +PDF_END.length];
            System.arraycopy(pdf, 0, result, 0, result.length);
            return result;
        }else {
            return null;
        }


    }

    /// <param name="srcBytes">源数组</param>
    /// <param name="searchBytes">查找的数组</param>
    /// <returns>返回的索引位置；否则返回值为 -1。</returns>
    private static int ByteIndexOf(byte[] srcBytes, byte[] searchBytes)
    {
        if (srcBytes == null) { return -1; }
        if (searchBytes == null) { return -1; }
        if (srcBytes.length == 0) { return -1; }
        if (searchBytes.length == 0) { return -1; }
        if (srcBytes.length < searchBytes.length) { return -1; }
        for (int i = 0; i <= srcBytes.length - searchBytes.length; i++)
        {
            if (srcBytes[i] == searchBytes[0])
            {
                //System.out.printf("%d: %d %d %d %d\n",i, srcBytes[i],srcBytes[i+1],srcBytes[i+2],srcBytes[i+3]);
                if (searchBytes.length == 1) { return i; }
                boolean flag = true;
                for (int j = 1; j < searchBytes.length; j++)
                {
                    if (srcBytes[i + j] != searchBytes[j])
                    {
                        flag = false;
                        break;
                    }
                }
                if (flag) { return i; }
            }
        }
        return -1;
    }

    private static byte[] byteMerger(byte[] bt1, byte[] bt2){
        byte[] bt3 = new byte[bt1.length+bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
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


        SESESPictrueInfo pic = sesSignature.getToSign().getEseal().getEsealInfo().getPicture();
        BigInteger height = pic.getHeight().getValue();
        BigInteger width = pic.getWidth().getValue();
        byte[] imgdata = pic.getData().getOctets();
        Image image = Image.getInstance(imgdata);
        appearance.setSignatureGraphic(image);

        float left_x = 200;
        float left_y = 200;
        float right_x = left_x + width.floatValue()*scale_w;
        float right_y = left_y + height.floatValue()*scale_h;

        // set position
        appearance.setVisibleSignature(new Rectangle(left_x, left_y, right_x, right_y), 1, SIGNATURE_NAME);
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        //appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);

        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
        dic.setReason(appearance.getReason());
        dic.setLocation(appearance.getLocation());
        dic.setContact(appearance.getContact());
        dic.setDate(new PdfDate(appearance.getSignDate()));
        appearance.setCryptoDictionary(dic);

        PdfDictionary dic2 = new PdfDictionary();
        byte[] paddedSig = sesSignature.getEncoded();

        int contentEstimated = paddedSig.length;
        HashMap<PdfName,Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
        appearance.preClose(exc);

        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        appearance.close(dic2);

        //ExternalDigest digest = new BouncyCastleDigest();
        //ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, null);
        //MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);

        try {
            if (stamper != null) {
                stamper.close();
            }
            if (reader != null) {
                reader.close();
            }
            if (os != null) {
                os.close();
            }

        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }

    public static byte[] getSignatures(String src) throws IOException, GeneralSecurityException {
        return getSignatures(src,true);
    }
    public static byte[] getSignatures(String src, boolean isYunjing) throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(src);

        AcroFields fields = reader.getAcroFields();

        ArrayList<String> names = fields.getSignatureNames();
        for (String name : names) {
            if(isYunjing){
                if(name.contains(SIGNATURE_NAME)){
                    PdfDictionary dic = fields.getSignatureDictionary(name);
                    PdfString obj = (PdfString)dic.get(PdfName.CONTENTS);
                    byte[] data = obj.getBytes();
                    return data;
                }
            }else{
                System.out.println("==" + name +"==");
                PdfDictionary dic = fields.getSignatureDictionary(name);
                Iterator i =  dic.getKeys().iterator();
                while(i.hasNext()){
                    PdfName pdfname = (PdfName)i.next();
                    PdfObject obj = dic.get(pdfname);
                    byte[] data = obj.getBytes();
                    if(data.length>0){

                        System.out.printf("%s := %s \n",pdfname.toString() , OtherUtil.bytesToHex(data));
                        String filename = "G://" +  pdfname.toString() + ".asn1";
                        File f = new File(filename);
                        if(!f.exists()){
                            f.createNewFile();
                        }
                        FileWriter wr = new FileWriter(f);
                        for(int k =0; k<data.length;k++){
                            wr.write(data[k]);
                        }
                        wr.close();
                    }else{
                        System.out.printf("%s := \n",pdfname.toString() );
                    }


                }
            }

        }
        return null;
    }

}
