package com.yunjingit.asn1;

import org.bouncycastle.asn1.*;

/*
    SES_ESPictrueInfo::=SEQUENCE{
    Type IA5String，--图片类型，如GIF、BMP、JPG
    Data OCTET STRING，--图片数据
    width INTEGER，--图片显示宽度，单位为毫米(mm)
    height INTEGER--图片显示高度，单位为毫米(mm)
    }

 */
public class SESESPictrueInfo extends ASN1Object {

    private DERIA5String type;
    private ASN1OctetString data;
    private ASN1Integer width;
    private ASN1Integer height;

    public SESESPictrueInfo(DERIA5String type, ASN1OctetString data, ASN1Integer width,ASN1Integer height ){
        this.type =type;
        this.data = data;
        this.width = width;
        this.height = height;
    }

    public SESESPictrueInfo(ASN1Sequence seq){
        type =DERIA5String.getInstance(seq.getObjectAt(0));
        data = DEROctetString.getInstance(seq.getObjectAt(1));
        width = ASN1Integer.getInstance(seq.getObjectAt(2));
        height = ASN1Integer.getInstance(seq.getObjectAt(3));
    }

    public static SESESPictrueInfo getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SESESPictrueInfo getInstance(
            Object  obj)
    {
        if (obj instanceof SESSignature)
        {
            return (SESESPictrueInfo)obj;
        }
        else if (obj != null)
        {
            return new SESESPictrueInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getHeight() {
        return height;
    }

    public ASN1Integer getWidth() {
        return width;
    }

    public ASN1OctetString getData() {
        return data;
    }

    public DERIA5String getType() {
        return type;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(type);
        v.add(data);
        v.add(width);
        v.add(height);

        return new DERSequence(v);
    }
}
