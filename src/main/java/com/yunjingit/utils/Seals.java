package com.yunjingit.utils;

import com.yunjingit.asn1.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Date;

public class Seals {

    static BigInteger VERSION =  BigInteger.valueOf(11);
    static ASN1ObjectIdentifier SM2signatureAlgorithm = new ASN1ObjectIdentifier("1.2.156.10197.1.501");
    static DERIA5String VID = new DERIA5String("yunjingit.com");
    static SM2Signer SM2SINGER = new SM2Signer();

    public static SESSignature esSignatureSign(byte[] contents, SESeal stamp, Certificate signercert, String propertyInfo , ECPrivateKeyParameters ecPriv){

        //a
        boolean result = Certifications.certificateVerify((X509Certificate) signercert);
        if(!result){
            // cert is not valid
            return null;
        }
        try {
            int result_i = esealVerify(stamp.getEncoded(),null);
            if(result_i!= 1){
                //TODO:log  stamp is not valid
                return null;
            }
        } catch (IOException e) {
            e.printStackTrace();
            //TODO:log  stamp is not valid
            return null;
        }
        //
        boolean found = false;
         ASN1Sequence certlist = stamp.getEsealInfo().getProperty().getCertList();
        try {
            byte[] certData = signercert.getEncoded();
            for (int i=0; i< certlist.size();i++){
                ASN1Encodable c = certlist.getObjectAt(i);
                int result_i = Arrays.compareUnsigned(certData, c.toASN1Primitive().getEncoded());
                if (result_i == 0){
                    // found equal
                    found = true;
                }
            }
            if(!found){
                //TODO: log cert is not in the list
                return  null;
            }
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace(); // cert wrong
            return null;
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
        Time time = new Time(new Date()); // transfer to ASN1
        ASN1BitString timeInfo = null;
        try {
            timeInfo = new DERBitString(time.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
            //TODO: log
            return null;
        }
        TBSSign tbsSign = new TBSSign(version,stamp , timeInfo, dataHash, propertyInfo_ia5, cert,SM2signatureAlgorithm );
        byte[] msg ;
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

    public static boolean esSignatureVerity(byte[] contents, byte[] sealsignature){

        ASN1StreamParser aIn = new ASN1StreamParser(sealsignature);

        ASN1SequenceParser    seq;
        SESSignature essignature;
        try {
            seq = (ASN1SequenceParser)aIn.readObject();
            essignature =  SESSignature.getInstance(seq);// 格式正确
        } catch (IOException e) {
            //TODO: log
            e.printStackTrace();
            return false;
        }


        try {
            byte[] signature = essignature.getSignature().getBytes();
            byte[] tbsign = essignature.getToSign().getEncoded();
            SM2Signer signer = new SM2Signer();
            byte[] certdata = essignature.getToSign().getCert().getEncoded();
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            Certificate signercert = cf.generateCertificate(new ByteArrayInputStream(certdata));
            ECPublicKeyParameters param = getEcPublicKeyParameters(signercert);
            if(param == null){
                // something wrong with extract PUBLIC key
                return false;
            }
            //signature vaild
            signer.init(false, param);
            signer.update(tbsign, 0, tbsign.length);
            boolean result = signer.verifySignature(signature);
            if (!result){
                //TODO: log verify failed
                return false;
            }

            ASN1BitString timeInfo = essignature.getToSign().getTimeInfo();
           String timestr = timeInfo.getString();
            ASN1UTCTime time = new ASN1UTCTime(timestr);
             result = Certifications.certificateVerify((X509Certificate) signercert, time.getDate(),false);
            if(!result){
                return false; // cert not vaild
            }

            // verify hash
            DERIA5String proper = essignature.getToSign().getPropertyInfo();
            String propertyInfo = proper.getString();
            byte[] data = processContents(contents, propertyInfo);
            SM3Digest digest = new SM3Digest();
            digest.reset();
            digest.update(data, 0, data.length);
            byte[] resBuf = new byte[digest.getDigestSize()];
            digest.doFinal(resBuf, 0);
            ASN1BitString datahash = essignature.getToSign().getDataHash();
            byte[] dataHash  = datahash.getEncoded();
            int result_i = Arrays.compareUnsigned(dataHash, resBuf);
            if (result_i != 0){
                return false; // hash failed
            }

            //verify stamp
            byte[] stampdata = essignature.getToSign().getEseal().getEncoded();
            result_i = esealVerify(stampdata, time.getDate());
            if(result_i != 1){
                // verify stamp failed
                return false;
            }
        } catch (IOException | CertificateException | NoSuchProviderException | ParseException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * Eseal verify int.
     *
     * @param stampdata the stampdata
     * @param refDate   the reference date
     * @return the int  1 successful; 2 wrong format; 80 not support in this impl; 3 signature wrong; 4 maker cert is invaild; 5 overdue
     */
    public static int esealVerify(byte[]  stampdata, Date refDate){

        SESeal stamp=null;
        byte[] msg = null;
        byte[] signature;
        ASN1ObjectIdentifier algo;
        ASN1OctetString cert;
        ECPublicKeyParameters param;
        Certificate signercert;

        Date enddate;
        Date startdate;

        //step a
        try {
            ASN1StreamParser aIn = new ASN1StreamParser(stampdata);
            ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
            stamp =  SESeal.getInstance(seq); //电子印章格式符合

            SESSealInfo esealInfo = stamp.getEsealInfo();
            cert = stamp.getSignInfo().getCert();
            algo = stamp.getSignInfo().getSignatureAlgorithm();
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(esealInfo);
            v.add(cert);
            v.add(algo);
            DERSequence se =  new DERSequence(v);
            msg = se.getEncoded();
            signature = stamp.getSignInfo().getSignData().getEncoded();
            CertificateFactory cf = null;
            try {
                cf = CertificateFactory.getInstance("X.509", "BC");
                signercert = cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
                param = getEcPublicKeyParameters(signercert);
                if(param == null){
                    // something wrong with extract PUBLIC key
                    return 2;
                }
            } catch (CertificateException e) {
                e.printStackTrace();
                return 2;
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
                return 2;
            }

            ASN1UTCTime end = stamp.getEsealInfo().getProperty().getValidEnd();
            ASN1UTCTime start = stamp.getEsealInfo().getProperty().getValidStart();
            try {
                enddate = end.getDate();
                startdate = start.getDate();
            } catch (ParseException e) {
                e.printStackTrace();
                return 2;
            }


        } catch (IOException e) {
            e.printStackTrace();
            return 2;// wrong format
        }

        //step b
         if(algo.equals(SM2signatureAlgorithm)){ //SM2

                SM2SINGER.init(false,param);
                SM2SINGER.update(msg, 0, msg.length);
                boolean result = SM2SINGER.verifySignature(signature);
                if(!result){
                    // signature verification fail
                    return 3;
                }
            }else{
                // not support RSA
                return 80;
            }

        //step c
        boolean result = Certifications.certificateVerify((X509Certificate) signercert);
        if(!result){
            // cert verified fail
            return 4;
        }

        //step d
        Date date = new Date();
        if(refDate!=null){
            date = refDate;
        }
        if(!date.before(startdate) && !date.after(enddate)){
            return 1;
        }else {
            return 5;
        }

    }

    public static ECPublicKeyParameters getEcPublicKeyParameters(Certificate cert) {
        PublicKey publicKey =cert.getPublicKey();
        ECPublicKeyParameters param = null;
        if (publicKey instanceof BCECPublicKey)
        {
            BCECPublicKey localECPublicKey = (BCECPublicKey)publicKey;
            ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                    localECParameterSpec.getG(), localECParameterSpec.getN());
            param = new ECPublicKeyParameters(localECPublicKey.getQ(),localECDomainParameters);
        }
        return param;
    }

    public static SESeal esealGenerate(String esID, int type, String name, org.bouncycastle.asn1.x509.Certificate[] certlist, Date start, Date end, SESESPictrueInfo pic,
                                       org.bouncycastle.asn1.x509.Certificate makercert, ECPrivateKeyParameters ecPriv){

        ASN1Integer version = new ASN1Integer(VERSION);
        SESHeader header = new SESHeader(version,VID);

        DERIA5String esID_ia5 = new DERIA5String(esID);

        ASN1Integer type_asn1 = new ASN1Integer(type);
        DERUTF8String name_asn1 = new DERUTF8String(name);

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for(org.bouncycastle.asn1.x509.Certificate c: certlist){
            vec.add(c);
        }
        DERSequence cert_seq = new DERSequence(vec);

        DERUTCTime start_asn1 = new DERUTCTime(start);
        DERUTCTime end_asn1 = new DERUTCTime(end);
        DERUTCTime create_asn1 = new DERUTCTime(new Date());
        SESESPropertyInfo propertyInfo = new SESESPropertyInfo(type_asn1,name_asn1,cert_seq,create_asn1,start_asn1,end_asn1);

        SESSealInfo esealInfo = new SESSealInfo(header,esID_ia5,propertyInfo,pic, null);
        try {
            DEROctetString cert = new DEROctetString(makercert.getEncoded());
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(esealInfo);
            v.add(cert);
            v.add(SM2signatureAlgorithm);
            DERSequence se =  new DERSequence(v);
            byte[] msg = se.getEncoded();
            SM2Signer signer = new SM2Signer();

            signer.init(true,ecPriv);
            signer.update(msg, 0, msg.length);
            byte[] sign = signer.generateSignature();
            DERBitString signData = new DERBitString(sign);
            SESSignInfo signInfo = new SESSignInfo(cert,SM2signatureAlgorithm, signData);

            return new SESeal(esealInfo,signInfo);
        } catch (IOException | CryptoException e) {
            e.printStackTrace();
            return null;
        }

    }


    public static SESESPictrueInfo pictrueInfoBuilder(String imgfile, int widthinmm, int heightinmm){

        try {
            FileInputStream is = new FileInputStream(imgfile);
            int i = 0; // 得到文件大小
            i = is.available();
            byte imgdata[] = new byte[i];
            is.read(imgdata);
            is.close();

            String[] s = imgfile.split("\\.");
            DERIA5String type = new DERIA5String(s[s.length-1]);
            ASN1OctetString data = new DEROctetString(imgdata);
            ASN1Integer width = new ASN1Integer(widthinmm);
            ASN1Integer height = new ASN1Integer(heightinmm);

            SESESPictrueInfo sesesPictrueInfo = new SESESPictrueInfo(type,data,width,height);
            return sesesPictrueInfo;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }




public static boolean exportSESeal(SESeal seSeal, String filename){

    try {
        byte[] data = seSeal.getEncoded();
        PemObject key =  new PemObject("SESEAL", data);
        PemWriter wr = new PemWriter(new FileWriter(filename,false));
        wr.writeObject(key);
        wr.close();
        return true;
    } catch (IOException e) {
        e.printStackTrace();
        return  false;
    }


}

public static SESeal importSESeal(String filename){

    try {
        PemReader rd = new PemReader(new FileReader(filename));
        PemObject keyobj = null;
        keyobj = rd.readPemObject();
        SESeal seal = SESeal.getInstance(ASN1Primitive.fromByteArray(keyobj.getContent()));
        return seal;
    } catch (IOException e) {
        e.printStackTrace();
        return null;
    }

}


}