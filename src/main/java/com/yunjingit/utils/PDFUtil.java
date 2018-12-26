package com.yunjingit.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class PDFUtil {

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

}
