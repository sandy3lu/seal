package com.yunjingit.utils;

import com.yunjingit.asn1.SESESPictrueInfo;
import com.yunjingit.asn1.SESSignature;
import com.yunjingit.asn1.SESeal;
import com.yunjingit.asn1.TBSSign;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.Date;

public class Seals {

    static BigInteger VERSION =  BigInteger.valueOf(11);


    public static SESSignature sealSign(byte[] contents, SESeal stamp, Certificate signercert, String propertyInfo , ECPrivateKeyParameters ecPriv){

        //a
        Certifications.certificateVerity((X509Certificate) signercert);

        try {
            if(!stampVerify(stamp.getEncoded())){
                //TODO:log
                return null;
            }
        } catch (IOException e) {
            e.printStackTrace();
            //TODO:log
            return null;
        }
        //
        boolean found = false;
         ASN1Sequence certlist = stamp.getEsealInfo().getProperty().getCertList();
        for (int i=0; i< certlist.size();i++){
            if (certlist.getObjectAt(i).equals(signercert)){
                // found equal
                found = true;
            }
        }
        if(!found){
            //TODO: log
            return  null;
        }

        byte[] data = processContents(contents, propertyInfo);
        SM3Digest digest = new SM3Digest();
        digest.reset();
        digest.update(data, 0, data.length);
        byte[] resBuf = new byte[digest.getDigestSize()];
        digest.doFinal(resBuf, 0);

        //tobSign
        ASN1Integer version = new ASN1Integer(VERSION);
        ASN1BitString dataHash = new DERBitString(resBuf);
        DERIA5String propertyInfo_ia5 = new DERIA5String(propertyInfo);
        ASN1OctetString cert = null;
        try {
            cert = new DEROctetString(signercert.getEncoded());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
            //TODO: log
            return null;
        }

        //sm2
        ASN1ObjectIdentifier signatureAlgorithm = new ASN1ObjectIdentifier("1.2.156.10197.1.501");
        Time time = new Time(new Date());
        ASN1BitString timeInfo = null;
        try {
            timeInfo = new DERBitString(time.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
            //TODO: log
            return null;
        }
        TBSSign tbsSign = new TBSSign(version,stamp , timeInfo, dataHash, propertyInfo_ia5, cert,signatureAlgorithm );
        byte[] msg = new byte[0];
        try {
            msg = tbsSign.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
            //TODO: log
            return null;
        }

        // TODO: how to get private key ecPriv
        SM2Signer signer = new SM2Signer();
        signer.init(true,ecPriv);
        signer.update(msg, 0, msg.length);

        try {
            byte[] sig = signer.generateSignature();
            ASN1BitString signature = new DERBitString(sig);
            return new SESSignature(tbsSign,signature);
        } catch (CryptoException e) {
            //TODO: log
            e.printStackTrace();
        }
        return null;
    }

    protected static byte[] processContents(byte[] input, String propertyInfo){
        return input;
    }

    public static boolean sealVerity(byte[] sealsignature){

        ASN1StreamParser aIn = new ASN1StreamParser(sealsignature);

        ASN1SequenceParser    seq = null;
        SESSignature essignature=null;
        try {
            seq = (ASN1SequenceParser)aIn.readObject();
            essignature =  SESSignature.getInstance(seq);
        } catch (IOException e) {
            //TODO: log
            e.printStackTrace();
            return false;
        }

        //TODO: signature vaild
        try {
            byte[] signature = essignature.getSignature().getBytes();
            byte[] tbsign = essignature.getToSign().getEncoded();
            SM2Signer signer = new SM2Signer();
            byte[] certdata = essignature.getToSign().getCert().getEncoded();
            String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

            Certificate c = cf.generateCertificate(new ByteArrayInputStream(certdata));
            (X509Certificate)c.getPublicKey();
            ECPublicKeyParameters ecPub = new ECPublicKeyParameters();
            signer.init(false, ecPub);
            signer.update(tbsign, 0, tbsign.length);
            boolean result = signer.verifySignature(signature);
            if (!result){
                //TODO: log

                return false;
            }
        } catch (IOException | CertificateException | NoSuchProviderException e) {
            e.printStackTrace();
        }






    }

    public static boolean stampVerify(byte[]  stampdata){

        ASN1StreamParser aIn = new ASN1StreamParser(stampdata);

        ASN1SequenceParser    seq = null;
        try {
            seq = (ASN1SequenceParser)aIn.readObject();
            SESeal stamp =  SESeal.getInstance(seq);

            //TODO: signature vaild

            //


        } catch (IOException e) {
            //TODO: log
            e.printStackTrace();
            return false;
        }




        return false;
    }

    public static SESeal esealGenerate(String esID, int type, String name, Certificate[] certlist, Date start, Date end, SESESPictrueInfo pic,
                                       Certificate makercert, ECPrivateKeyParameters ecPriv){



        return null;
    }


}
