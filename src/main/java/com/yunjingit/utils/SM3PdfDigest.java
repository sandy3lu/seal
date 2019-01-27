package com.yunjingit.utils;

import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import org.bouncycastle.jcajce.provider.digest.SM3;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class SM3PdfDigest implements ExternalDigest {
    @Override
    public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
        if(hashAlgorithm.toLowerCase().contains("sm3")) {
            return new SM3.Digest();
        }else{
            return new BouncyCastleDigest().getMessageDigest(hashAlgorithm);
        }
    }
}
