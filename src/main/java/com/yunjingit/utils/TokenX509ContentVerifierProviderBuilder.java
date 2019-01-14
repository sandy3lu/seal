package com.yunjingit.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class TokenX509ContentVerifierProviderBuilder implements X509ContentVerifierProviderBuilder {


    @Override
    public ContentVerifierProvider build(SubjectPublicKeyInfo subjectPublicKeyInfo) throws OperatorCreationException {
        return build(convertPublicKey(subjectPublicKeyInfo));

    }

    @Override
    public ContentVerifierProvider build(X509CertificateHolder x509CertificateHolder) throws OperatorCreationException {
        return null;
    }



    public PublicKey convertPublicKey(SubjectPublicKeyInfo publicKeyInfo)
            throws OperatorCreationException
    {
        try
        {
            KeyFactory keyFact = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);

            return keyFact.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        }
        catch (IOException e)
        {
            throw new OperatorCreationException("cannot get encoded form of key: " + e.getMessage(), e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new OperatorCreationException("cannot create key factory: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new OperatorCreationException("cannot find factory provider: " + e.getMessage(), e);
        }
        catch (InvalidKeySpecException e)
        {
            throw new OperatorCreationException("cannot create key factory: " + e.getMessage(), e);
        }
    }


    public ContentVerifierProvider build(final PublicKey publicKey)
    {
        return new ContentVerifierProvider()
        {

            @Override
            public boolean hasAssociatedCertificate()
            {
                return false;
            }
            @Override
            public X509CertificateHolder getAssociatedCertificate()
            {
                return null;
            }
            @Override
            public ContentVerifier get(AlgorithmIdentifier algorithm)
            {
                return new SM2sigContentVerifier(algorithm, publicKey);
            }



        };
    }
}


class SM2sigContentVerifier implements ContentVerifier{

    SM2Signer signer;
    static ASN1ObjectIdentifier SM2signatureAlgorithm = new ASN1ObjectIdentifier("1.2.156.10197.1.501");
    static AlgorithmIdentifier alg = new AlgorithmIdentifier(SM2signatureAlgorithm);

    ByteArrayOutputStream data;

    SM2sigContentVerifier(AlgorithmIdentifier algorithm, PublicKey publicKey){

        if(algorithm.getAlgorithm().equals(SM2signatureAlgorithm)) {
            signer = new SM2Signer();
            if (publicKey instanceof BCECPublicKey)
            {
                BCECPublicKey localECPublicKey = (BCECPublicKey)publicKey;
                ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
                ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                        localECParameterSpec.getG(), localECParameterSpec.getN());
                ECPublicKeyParameters param = new ECPublicKeyParameters(localECPublicKey.getQ(),localECDomainParameters);
                signer.init(false, param);
            }
            data = new ByteArrayOutputStream();
        }
    }


    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return alg;
    }

    @Override
    public OutputStream getOutputStream() {
        return data;
    }

    @Override
    public boolean verify(byte[] expected) {
        System.out.println("verify ....\n");
        byte[] contents = data.toByteArray();
        signer.update(contents,0,contents.length);
        return signer.verifySignature(expected);

    }
}
