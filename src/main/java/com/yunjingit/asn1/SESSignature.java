package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;


public class SESSignature extends ASN1Object {
    private TBSSign toSign;
    private ASN1BitString signature;

    public SESSignature(TBSSign toSign, ASN1BitString signature){
        this.toSign = toSign;
        this.signature = signature;
    }

    private SESSignature(
            ASN1Sequence    seq)
    {
        toSign = TBSSign.getInstance(seq.getObjectAt(0));
        signature = DERBitString.getInstance(seq.getObjectAt(1)); // no BERBitString class

    }

    public static SESSignature getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SESSignature getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (SESSignature)obj;
        }
        else if (obj != null)
        {
            return new SESSignature(ASN1Sequence.getInstance(obj));
        }

        return null;
    }



    public TBSSign getToSign() {
        return toSign;
    }

    public ASN1BitString getSignature() {
        return signature;
    }

    public  ASN1Primitive toASN1Primitive(){

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(toSign);
        v.add(signature);
        return new DERSequence(v);
    }
}
