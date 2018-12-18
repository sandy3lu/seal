package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;

/*
电子印章数据的ASN.1定义为：
    SESeal::=SEQUENCE{
    esealInfo  SES_SealInfo
    signInfo   SES_SignInfo
    }

 */
public class SESeal extends ASN1Object {
    private SESSealInfo esealInfo;
    private SESSignInfo signInfo;

    public SESeal(SESSealInfo esealInfo, SESSignInfo signInfo){
        this.esealInfo = esealInfo;
        this.signInfo = signInfo;
    }

    private SESeal(
            ASN1Sequence seq)
    {
        esealInfo = SESSealInfo.getInstance(seq.getObjectAt(0));
        signInfo = SESSignInfo.getInstance(seq.getObjectAt(1));

    }

    public static SESeal getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SESeal getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (SESeal)obj;
        }
        else if (obj != null)
        {
            return new SESeal(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
    public SESSealInfo getEsealInfo() {
        return esealInfo;
    }

    public SESSignInfo getSignInfo() {
        return signInfo;
    }

    public ASN1Primitive toASN1Primitive(){

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(esealInfo);
        v.add(signInfo);
        return new DERSequence(v);

    }
}
