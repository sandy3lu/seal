package com.yunjingit.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

import static org.junit.Assert.*;

public class KeysTest {

    @Test
    public void generateSM2KeyPair() {
        try {
            KeyPair kp = Keys.generateSM2KeyPair();
            ECPrivateKey pk_ori = (ECPrivateKey) kp.getPrivate();
            byte[] keydata = pk_ori.getS().toByteArray();

            BigInteger d = new BigInteger(keydata); // recover a private key from only D

            X9ECParameters ecparam = CustomNamedCurves.getByName("sm2p256v1");

            ECDomainParameters domain = new ECDomainParameters(ecparam.getCurve(), ecparam.getG(), ecparam.getN());
            ECPrivateKeyParameters param = new ECPrivateKeyParameters(d,domain);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(param);
            BCECPrivateKey key = (BCECPrivateKey)BouncyCastleProvider.getPrivateKey(privateKeyInfo);
            if(key.getD() == pk_ori.getS()){
                assert true;
            }

        } catch (Exception e) {
            e.printStackTrace();
            assert false;
        }


    }
}