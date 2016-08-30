package com.mendix.ssltools;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Scanner;

public class Util {
    public byte[] readKeyMaterial(String base64WithMarkers, String beginMarker, String endMarker) throws IOException
    {
        String line = null;
        StringBuffer    buf = new StringBuffer();
        Scanner scanner = new Scanner(base64WithMarkers);
        while (scanner.hasNextLine())
        {
            line = scanner.nextLine();
            if (line.contains(beginMarker)){
                continue;
            }
            if (line.contains(endMarker)) {
                return DatatypeConverter.parseBase64Binary(buf.toString());
            }
            buf.append(line.trim());
        }

        throw new IOException("Invalid PEM file: No end marker"); //$NON-NLS-1$
    }

    public String derToPem(byte[] der, String beginMarker, String endMarker) {
        String base64 = DatatypeConverter.printBase64Binary(der);
        String[] lines = base64.split("(?<=\\G.{64})");
        String result = beginMarker + "\n";
        for (String line : lines) {
            result += line + "\n";
        }
        result += endMarker;
        return result;
    }

    public String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }
}
