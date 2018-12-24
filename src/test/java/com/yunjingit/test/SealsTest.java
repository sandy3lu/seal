package com.yunjingit.test;

import org.junit.Test; 
import org.junit.Before; 
import org.junit.After; 

/** 
* Seals Tester. 
* 
* @author <Authors name> 
* @since <pre>Ê®¶þÔÂ 24, 2018</pre> 
* @version 1.0 
*/ 
public class SealsTest { 

@Before
public void before() throws Exception {



} 

@After
public void after() throws Exception { 
} 

/** 
* 
* Method: esSignatureSign(byte[] contents, SESeal stamp, Certificate signercert, String propertyInfo, ECPrivateKeyParameters ecPriv)
* 
*/ 
@Test
public void testEsSignatureSign() throws Exception {
//TODO: Test goes here... 
} 

/** 
* 
* Method: processContents(byte[] input, String propertyInfo) 
* 
*/ 
@Test
public void testProcessContents() throws Exception { 
//TODO: Test goes here... 
} 

/** 
* 
* Method: esSignatureVerity(byte[] contents, byte[] sealsignature)
* 
*/ 
@Test
public void testEsSignatureVerity() throws Exception {
//TODO: Test goes here... 
} 

/** 
* 
* Method: esealVerify(byte[]  stampdata, Date refDate)
* 
*/ 
@Test
public void testEsealVerify() throws Exception {
//TODO: Test goes here... 
} 

/** 
* 
* Method: esealGenerate(String esID, int type, String name, org.bouncycastle.asn1.x509.Certificate[] certlist, Date start, Date end, SESESPictrueInfo pic, org.bouncycastle.asn1.x509.Certificate makercert, ECPrivateKeyParameters ecPriv) 
* 
*/ 
@Test
public void testEsealGenerate() throws Exception { 
//TODO: Test goes here... 
} 


/** 
* 
* Method: getEcPublicKeyParameters(Certificate cert) 
* 
*/ 
@Test
public void testGetEcPublicKeyParameters() throws Exception { 
//TODO: Test goes here... 
/* 
try { 
   Method method = Seals.getClass().getMethod("getEcPublicKeyParameters", Certificate.class); 
   method.setAccessible(true); 
   method.invoke(<Object>, <Parameters>); 
} catch(NoSuchMethodException e) { 
} catch(IllegalAccessException e) { 
} catch(InvocationTargetException e) { 
} 
*/ 
} 

} 
