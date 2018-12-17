package com.yunjingit.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;

public class CertificationTest extends TestCase {






    public static TestSuite suite()
    {
        return new TestSuite(CertificationTest.class);
    }

    public static void main(String[] args)
            throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }
}
