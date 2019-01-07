package com.yunjingit.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

public class Keys {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Create a random keysize(i.e. 2048) bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair(int keysize)
            throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(keysize, new SecureRandom());

        return kpGen.generateKeyPair();
    }



    public static KeyPair generateSM2KeyPair()
            throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

        g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

        return g.generateKeyPair();
    }

}
