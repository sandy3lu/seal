package com.yunjingit.utils;

public class ESealException extends Exception {

    public static ESealException CERT_VERIFIED_ERROR = new ESealException("Certification verification failed");

    public static ESealException ESEAL_VERIFIED_ERROR = new ESealException("ESeal verification failed");
    public static ESealException CERT_NOT_IN_LIST_ERROR = new ESealException("Certification is not in the list");
    public static ESealException CERT_FORMAT_ERROR = new ESealException("Certification format error");
    public static ESealException ASN1_FORMAT_ERROR = new ESealException("ASN1 format error");
    public static ESealException CRYPTO_ERROR = new ESealException("Crypto error");
    public static ESealException ESEAL_SIGNATURE_FORMAT_ERROR = new ESealException("Eseal signature format error");
    public static ESealException ESEAL_SIGNATURE_VERIFIED_ERROR = new ESealException("Eseal signature format error");
    public static ESealException ESEAL_MISSING_BC_ERROR = new ESealException("need Bouncy Castle lib");
    public static ESealException ESEAL_NOT_SUPPORT_ERROR = new ESealException("not support now");
    public static ESealException ESEAL_OVERDUE_ERROR = new ESealException("ESeal is overdue");


    public ESealException(){

        super();
    }


    public ESealException(String message){
        super(message);

    }


    public ESealException(String message, Throwable cause){

        super(message,cause);
    }


    public ESealException(Throwable cause) {

        super(cause);
    }

}

