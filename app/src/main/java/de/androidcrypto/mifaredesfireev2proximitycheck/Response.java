package de.androidcrypto.mifaredesfireev2proximitycheck;

import java.util.Arrays;

/**
 * This class takes the response of a sendData command to/from a Mifare DESFire EV1/EV2/EV3 card
 */

public class Response {
    private byte[] data;
    private byte sw1;
    private byte sw2;

    public Response(byte[] fullData) {

        // here we are splitting the fullData
        if (fullData.length < 2) {
            this.data = null;
            this.sw1 = (byte) 0xFF;
            this.sw2 = (byte) 0xFF;
        }
        this.data = Arrays.copyOf(fullData, fullData.length - 2);
        this.sw1 = fullData[fullData.length - 1];
        this.sw2 = fullData[fullData.length - 0];
    }

    public byte[] getData() {
        return data;
    }

    public byte getSw1() {
        return sw1;
    }

    public byte getSw2() {
        return sw2;
    }
}
