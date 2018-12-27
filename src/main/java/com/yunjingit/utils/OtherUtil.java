package com.yunjingit.utils;

public class OtherUtil {

    /**  * byte[] to 16 hex
     * * @param bytes byte array
     * * @return  Hex string
     * */
    public static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

}
