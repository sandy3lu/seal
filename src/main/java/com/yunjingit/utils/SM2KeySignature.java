package com.yunjingit.utils;

import com.itextpdf.text.pdf.security.ExternalSignature;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;


public class SM2KeySignature implements ExternalSignature {
    private PrivateKey pk;
    public SM2KeySignature(PrivateKey pk){
        this.pk = pk;
    }
    @Override
    public String getHashAlgorithm() {
        return "SHA256";//"SM3";
    }

    @Override
    public String getEncryptionAlgorithm() {
        return "RSA";//"SM2";
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {

        SM2Signer sig = new SM2Signer();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) pk;
        ECCurve curve = new SM2P256V1Curve();
        BigInteger SM2_ECC_N = new BigInteger(
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
        BigInteger SM2_ECC_GX = new BigInteger(
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
        BigInteger SM2_ECC_GY = new BigInteger(
                "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
        ECPoint G_POINT = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        ECDomainParameters ecDomainParameters = new ECDomainParameters(curve,G_POINT,SM2_ECC_N  );
        ECKeyParameters ecKeyParameters = new ECPrivateKeyParameters(ecPrivateKey.getS(),ecDomainParameters);
        sig.init(true, ecKeyParameters);
        sig.update(message,0,message.length);
        try {
            return sig.generateSignature();
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }



}
