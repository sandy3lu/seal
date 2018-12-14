package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;

/*
    ExtensionDatas::=SEQUENCE SIZE (O..MAX) OF ExtData
    ExtData::=SEQUENCE{
    extnID     OBJECT IDENTIFIER，--自定义扩展字段标识
    critical     BOOLEAN DEFAULT FALSE，--自定义扩展字段是否关键
    extnValue   OCTET STRING--自定义扩展字段数据值
    }

 */
public class ExtensionDatas extends ASN1Sequence{


}





class ExtData extends ASN1Object{
    private ASN1ObjectIdentifier extnID;
    private ASN1Boolean critial = ASN1Boolean.FALSE; // default, DER will not encoding
    private ASN1OctetString extnValue;

    public ExtData(ASN1ObjectIdentifier extnID, ASN1Boolean critial,ASN1OctetString extnValue ){
        this.extnID = extnID;
        this.critial = critial;
        this.extnValue = extnValue;
    }

    public ExtData(ASN1Sequence seq){
        extnID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        if(seq.size()>2){
            critial = ASN1Boolean.getInstance(seq.getObjectAt(1));
        }
        extnValue = ASN1OctetString.getInstance(seq.getObjectAt(seq.size()-1));

    }

    public static ExtData getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ExtData getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (ExtData)obj;
        }
        else if (obj != null)
        {
            return new ExtData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }




    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(extnID);
        if(critial.isTrue()) {
            v.add(critial);
        }
        v.add(extnValue);

        return new DERSequence(v);
    }
}


