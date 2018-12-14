package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;

public class TBSSign extends ASN1Object {
    private ASN1Integer version;
    private SESeal eseal;
    private ASN1BitString timeInfo;
    private ASN1BitString dataHash;
    private DERIA5String propertyInfo;
    private ASN1OctetString cert;
    private ASN1ObjectIdentifier signatureAlgorithm;

    public TBSSign(ASN1Integer version, SESeal eseal, ASN1BitString timeInfo, ASN1BitString dataHash, DERIA5String propertyInfo, ASN1OctetString cert,ASN1ObjectIdentifier signatureAlgorithm ){
        this.version = version;
        this.eseal = eseal;
        this.timeInfo = timeInfo;
        this.dataHash = dataHash;
        this.propertyInfo = propertyInfo;
        this.cert = cert;
        this.signatureAlgorithm = signatureAlgorithm;

    }

    private TBSSign(
            ASN1Sequence    seq)
    {
        version = ASN1Integer.getInstance(seq.getObjectAt(0));
        eseal = SESeal.getInstance(seq.getObjectAt(1));
        timeInfo = DERBitString.getInstance(seq.getObjectAt(2));
        dataHash = DERBitString.getInstance(seq.getObjectAt(3));;
        propertyInfo = DERIA5String.getInstance(seq.getObjectAt(4));
        cert = ASN1OctetString.getInstance(seq.getObjectAt(5));
        signatureAlgorithm = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(6));
    }


    public static TBSSign getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSSign getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (TBSSign)obj;
        }
        else if (obj != null)
        {
            return new TBSSign(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1BitString getDataHash() {
        return dataHash;
    }

    public ASN1BitString getTimeInfo() {
        return timeInfo;
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public ASN1ObjectIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public ASN1OctetString getCert() {
        return cert;
    }

    public DERIA5String getPropertyInfo() {
        return propertyInfo;
    }

    public SESeal getEseal() {
        return eseal;
    }

    public ASN1Primitive toASN1Primitive(){

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(version);
        v.add(eseal);
        v.add(timeInfo);
        v.add(dataHash);
        v.add(propertyInfo);
        v.add(cert);
        v.add(signatureAlgorithm);
        return new DERSequence(v);

    }
}
