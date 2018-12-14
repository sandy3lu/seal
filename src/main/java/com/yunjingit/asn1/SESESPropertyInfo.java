package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;

/*
印章属性信息的ASN.1定义为：
 SES_ESPropertyInfo::=SEQUENCE{
        Type  INTEGER，--印章类型，如1为单位印章，2为个人印章
        Name  UTF8String，--印章名称，如个人章、公章、财务章
        certList  SEQUENCE OF cert，-- 签章人证书列表
        createDate  UTCTIME，--印章制作日期
        validStart   UTCTIME，--印章有效起始日期
        validEnd    UTCTIME--印章有效终止日期
   }

 */
public class SESESPropertyInfo extends ASN1Object {
    private ASN1Integer type;
    private DERUTF8String name;
    private ASN1Sequence certList;
    private ASN1UTCTime createDate;
    private ASN1UTCTime validStart;
    private ASN1UTCTime validEnd;

    public SESESPropertyInfo(ASN1Integer type,DERUTF8String name, ASN1Sequence certList, ASN1UTCTime createDate, ASN1UTCTime validStart, ASN1UTCTime validEnd){
        this.type = type;
        this.name = name;
        this.certList =certList;
        this.createDate = createDate;
        this.validStart = validStart;
        this.validEnd = validEnd;
    }

    public SESESPropertyInfo( ASN1Sequence    seq){
        type = ASN1Integer.getInstance(seq.getObjectAt(0));
        name = DERUTF8String.getInstance(seq.getObjectAt(1));
        certList =(ASN1Sequence)(seq.getObjectAt(2));
        createDate = ASN1UTCTime.getInstance(seq.getObjectAt(3));
        validStart = ASN1UTCTime.getInstance(seq.getObjectAt(4));
        validEnd =  ASN1UTCTime.getInstance(seq.getObjectAt(5));
    }

    public static SESESPropertyInfo getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SESESPropertyInfo getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (SESESPropertyInfo)obj;
        }
        else if (obj != null)
        {
            return new SESESPropertyInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getType() {
        return type;
    }

    public ASN1Sequence getCertList() {
        return certList;
    }

    public ASN1UTCTime getCreateDate() {
        return createDate;
    }

    public ASN1UTCTime getValidEnd() {
        return validEnd;
    }

    public ASN1UTCTime getValidStart() {
        return validStart;
    }

    public DERUTF8String getName() {
        return name;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(type);
        v.add(name);
        v.add(certList);
        v.add(createDate);
        v.add(validStart);
        v.add(validEnd);
        return new DERSequence(v);
    }
}
