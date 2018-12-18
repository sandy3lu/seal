package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;

/*
    SES_SignInfo::=SEQUENCE{
    cert OCTET STRING
    signatureAlgorithm OBJECT IDENTIFIER
    signData BIT STRING
      }

 */
public class SESSignInfo extends ASN1Object {

    private ASN1OctetString cert;
    private ASN1ObjectIdentifier signatureAlgorithm;

    private ASN1BitString signData;

    public SESSignInfo( ASN1OctetString cert, ASN1ObjectIdentifier signatureAlgorithm, ASN1BitString signData){
        this.cert = cert;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signData = signData;


    }

    public SESSignInfo(ASN1Sequence seq){

        cert = ASN1OctetString.getInstance(seq.getObjectAt(0));
        signatureAlgorithm = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        signData = DERBitString.getInstance(seq.getObjectAt(2));

    }

    public static SESSignInfo getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SESSignInfo getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (SESSignInfo)obj;
        }
        else if (obj != null)
        {
            return new SESSignInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1OctetString getCert() {
        return cert;
    }

    public ASN1ObjectIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public ASN1BitString getSignData() {
        return signData;
    }

    public ASN1Primitive toASN1Primitive(){

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(cert);
        v.add(signatureAlgorithm);
        v.add(signData);

        return new DERSequence(v);

    }
}
