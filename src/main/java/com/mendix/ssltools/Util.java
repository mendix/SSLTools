package com.mendix.ssltools;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Base64;
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
                return Base64.getDecoder().decode(buf.toString());
            }
            buf.append(line.trim());
        }

        throw new IOException("Invalid PEM file: No end marker"); //$NON-NLS-1$
    }

    public String derToPem(byte[] der, String beginMarker, String endMarker) {
        String base64 = Base64.getEncoder().encodeToString(der);
        String[] lines = base64.split("(?<=\\G.{64})");
        StringBuilder result = new StringBuilder(beginMarker).append("\n");
        for (String line : lines) {
            result.append(line).append("\n");
        }
        result.append(endMarker);
        return result.toString();
    }

    public String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }
}
