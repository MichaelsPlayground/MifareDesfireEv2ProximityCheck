package de.androidcrypto.mifaredesfireev2proximitycheck;

import java.util.Arrays;

/**
 * This class takes the response of a sendData command to/from a Mifare DESFire EV1/EV2/EV3 card
 */

public class Response {
    private byte[] command;
    private byte[] fullResponse;
    private byte[] data;
    private byte sw1;
    private byte sw2;

    public Response(byte[] command, byte[] fullResponse) {

        // some sanity checks
        if ((command == null) || (fullResponse == null)) {
            this.data = null;
            this.sw1 = (byte) 0xFF;
            this.sw2 = (byte) 0xFF;
        }
        if (fullResponse.length < 2) {
            this.data = null;
            this.sw1 = (byte) 0xFF;
            this.sw2 = (byte) 0xFF;
        }
        this.command = command;
        this.fullResponse = fullResponse;
        // here we are splitting the fullResponse
        this.data = Arrays.copyOf(fullResponse, fullResponse.length - 2);
        this.sw1 = fullResponse[fullResponse.length - 2];
        this.sw2 = fullResponse[fullResponse.length - 1];
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

    public byte[] getCommand() {
        return command;
    }

    public byte[] getFullResponse() {
        return fullResponse;
    }
}
