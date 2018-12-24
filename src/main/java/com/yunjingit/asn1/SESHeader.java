package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;
/*
SES_Header::=SEQUENCE{
    ID   IA5String
    version  INTEGER
    Vid  IA5String
}

 */
public class SESHeader extends ASN1Object {

    private DERIA5String ID = new DERIA5String("ES");
    private ASN1Integer version;
    private DERIA5String vid;

    public SESHeader(ASN1Integer version, DERIA5String vid){

        this.version = version;
        this.vid = vid;
    }

    public SESHeader(ASN1Sequence seq){
        ID = DERIA5String.getInstance(seq.getObjectAt(0));
        version = ASN1Integer.getInstance(seq.getObjectAt(1));
        vid =DERIA5String.getInstance(seq.getObjectAt(2));
    }

    public static SESHeader getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SESHeader getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (SESHeader)obj;
        }
        else if (obj != null)
        {
            return new SESHeader(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public DERIA5String getID() {
        return ID;
    }

    public DERIA5String getVid() {
        return vid;
    }

    public ASN1Primitive toASN1Primitive(){

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(ID);
        v.add(version);
        v.add(vid);
        return new DERSequence(v);

    }
}
