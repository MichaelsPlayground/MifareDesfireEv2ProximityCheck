package de.androidcrypto.mifaredesfireev2proximitycheck;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = "DF ProxCheck";
    TextView dumpField, readResult;
    private NfcAdapter mNfcAdapter;
    String dumpExportString = "";
    String tagIdString = "";
    String tagTypeString = "";
    private static final int REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE = 100;
    Context contextSave;

    /**
     * section for SESSION_KEYS and IV
     */

    private byte[] SESSION_KEY_DES = new byte[8]; // just temporary 0x00's, get filled in authenticateDes
    private byte[] SESSION_KEY_AES = new byte[16]; // just temporary 0x00's, get filled in authenticateAes
    private byte[] IV_DES = new byte[8]; // just temporary 0x00's, get filled in authenticateDes
    private byte[] IV_AES = new byte[16]; // just temporary 0x00's, get filled in authenticateAes

    /**
     * section constants for keys and AIDs
     */

    private final byte[] DES_KEY = new byte[8]; // default, 8 bytes filled with 0x00
    private final byte[] AES_KEY = new byte[16]; // default, 16 bytes filled with 0x00
    private final byte MASTER_KEY_NUMBER = (byte) 0x00;
    private final byte VC_CONFIGURATION_KEY_NUMBER = (byte) 0x20;
    private final byte VC_PROXIMITY_KEY_NUMBER = (byte) 0x21;
    private final byte[] MASTER_APPLICATION_ID = new byte[3];

    /**
     * section constants for commands
     */

    private final byte GET_UID = (byte) 0x51;
    private final byte SELECT_APPLICATION = (byte) 0x5A; // used to select the Master APPLICATION
    private final byte AUTH_DES = (byte) 0x1A;
    private final byte CHANGE_VC_CONFIGURATION_KEY = (byte) 0xC4; // changes the key 0x20 to an AES key

    /**
     * section constants for responses
     */

    private final byte SW1_OK = (byte) 0x91;
    private final byte SW2_OK = (byte) 0x00;
    private final byte SW2_MORE_DATA = (byte) 0xAF;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);
        contextSave = getApplicationContext();

        dumpField = findViewById(R.id.tvMainDump1);
        readResult = findViewById(R.id.tvMainReadResult);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        System.out.println("NFC tag discovered");
        runOnUiThread(() -> {
            readResult.setText("");
        });

        IsoDep isoDep = null;
        writeToUiAppend(readResult, "Tag found");
        String[] techList = tag.getTechList();
        for (int i = 0; i < techList.length; i++) {
            writeToUiAppend(readResult, "TechList: " + techList[i]);
        }
        String tagId = bytesToHex(tag.getId());
        writeToUiAppend(readResult, "TagId: " + tagId);

        try {
            isoDep = IsoDep.get(tag);

            if (isoDep != null) {
                runOnUiThread(() -> {
                    Toast.makeText(getApplicationContext(),
                            "NFC tag is IsoDep compatible",
                            Toast.LENGTH_SHORT).show();
                });

                // Make a Sound
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                isoDep.connect();
                dumpExportString = "";
                runOnUiThread(() -> {
                    //readResult.setText("");
                });


                writeToUiAppend(readResult, "IsoDep reading");

                /**
                 * to run the Mifare DESFire EV2/EV3 Proximity Check there are some preparations to go:
                 * a) select Master Application and authenticate with the (DES) Master Application Key
                 * b) change the VC Configuration Key (0x20) with an AES key using decryption (!) and CRC16
                 * c) authenticate with the VC Configuration Key - this is an AES authentication
                 * d) change the VC Proximity Key (0x21) with an AES key using decryption (!) and CRC32
                 *
                 * Check that both keys are set using the getKeyVersion command
                 *
                 * now we are ready to run the proximity check using 3 steps:
                 * a) PrepareProximityCheck
                 * b) RunProximityCheck (using just 1 as number of rounds
                 * c) VerifyProximityCheck
                 *
                 */

                // this is just for testing the getVersion command
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "GET UID");

                Response response = sendData(isoDep, GET_UID, null);
                writeToUiAppend(readResult, printData("data", response.getData()) + " sw1: " + response.getSw1() + " sw2: " + response.getSw2());
                if (!checkResponse(readResult, response)) {
                    //return;
                };

                // select the  Master APPLICATION
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "selectMasterApplication start");
                boolean result = selectApplicationDes(readResult, isoDep, MASTER_APPLICATION_ID, true, null);
                writeToUiAppend(readResult, "selectMasterApplication result: " + result);

                // authenticate with the PICC master key
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "authenticateDes start");
                result = authenticateDes(readResult, isoDep, MASTER_KEY_NUMBER, DES_KEY, true, null);
                writeToUiAppend(readResult, "authenticateDes result: " + result);

                // now we are trying to read the UID after authentication
                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "getUID start");
                response = sendData(isoDep, GET_UID, null);
                writeToUiAppend(readResult, printData("data", response.getData()) + " sw1: " + response.getSw1() + " sw2: " + response.getSw2());
                if (!checkResponse(readResult, response)) {
                    //return;
                };
                writeToUiAppend(readResult, printData("get UID", response.getData()));

                writeToUiAppend(readResult, "");
                writeToUiAppend(readResult, "change VC Configuration key start");
                result = changeVcConfigurationKey(readResult, isoDep, VC_CONFIGURATION_KEY_NUMBER, AES_KEY, AES_KEY, true, null);


            } else {
                writeToUiAppend(readResult, "IsoDep == null");
            }
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR IOException: " + e);
            e.printStackTrace();
        }
    }

    /**
     * section for changing the VC Configuration key
     */

    private boolean changeVcConfigurationKey(TextView readResult, IsoDep isoDep, byte vc_configuration_key_number, byte[] oldAesKey, byte[] newAesKey, boolean verbose, byte[] result) {



        return false;
    }


    /**
     * section for selecting the master application
     */

    private boolean selectApplicationDes(TextView logTextView, IsoDep isoDep, byte[] applicationIdentifier, boolean verbose, byte[] result) {
        try {
            writeToUiAppend(logTextView, "selectApplication for AID " + Utils.bytesToHex(applicationIdentifier));
            Response getSelectApplicationResponse = sendData(isoDep, SELECT_APPLICATION, applicationIdentifier);
            //byte[] getChallengeResponse = isoDep.transceive(wrapMessage(AUTH_DES, new byte[]{(byte) (keyId & 0xFF)}));
            if (verbose) {
                writeToUiAppend(logTextView, printData("getSelectApplicationCommand ", getSelectApplicationResponse.getCommand()));
                writeToUiAppend(logTextView, printData("getSelectApplicationResponse", getSelectApplicationResponse.getFullResponse()));
            }
            if (checkResponse(logTextView, getSelectApplicationResponse)) {
                return true;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "selectApplicationDes failed: " + e.getMessage());
            writeToUiAppend(logTextView, "selectApplicationDes failed: " + Arrays.toString(e.getStackTrace()));
            e.printStackTrace();
        }
        return false;
    }



    /**
     * section for authentication with DES
     */

    // if verbose = true all steps are printed out
    private boolean authenticateDes(TextView logTextView, IsoDep isoDep, byte keyId, byte[] key, boolean verbose, byte[] result) {
        try {
            writeToUiAppend(logTextView, "authenticateDes for keyId " + keyId + " and key " + Utils.bytesToHex(key));
            // do DES auth
            Response getChallengeResponse = sendData(isoDep, AUTH_DES, new byte[]{(byte) (keyId & 0xFF)});
            //byte[] getChallengeResponse = isoDep.transceive(wrapMessage(AUTH_DES, new byte[]{(byte) (keyId & 0xFF)}));
            if (verbose) {
                writeToUiAppend(logTextView, printData("getChallengeCommand ", getChallengeResponse.getCommand()));
                writeToUiAppend(logTextView, printData("getChallengeResponse", getChallengeResponse.getFullResponse()));
            }
            // cf5e0ee09862d90391af
            // 91 af at the end shows there is more data

            //byte[] challenge = Arrays.copyOf(getChallengeResponse, getChallengeResponse.length - 2);
            if (verbose) writeToUiAppend(logTextView, printData("challengeResponse", getChallengeResponse.getData()));

            // Of course the rndA shall be a random number,
            // but we will use a constant number to make the example easier.
            byte[] rndA = Utils.hexStringToByteArray("0001020304050607");
            if (verbose) writeToUiAppend(logTextView, printData("rndA", rndA));

            // This is the default key for a blank DESFire card.
            // defaultKey = 8 byte array = [0x00, ..., 0x00]
            //byte[] defaultDESKey = Utils.hexStringToByteArray("0000000000000000");
            //byte[] defaultDESKey = key.clone();
            byte[] IV = new byte[8];
            writeToUiAppend(logTextView, printData("IV at start", IV));

            // Decrypt the challenge with default keybyte[] rndB = decrypt(challenge, defaultDESKey, IV);
            byte[] rndB = decryptDes(getChallengeResponse.getData(), DES_KEY, IV);
            if (verbose) writeToUiAppend(logTextView, printData("rndB", rndB));
            // Rotate left the rndB byte[] leftRotatedRndB = rotateLeft(rndB);
            byte[] leftRotatedRndB = rotateLeft(rndB);
            if (verbose)
                writeToUiAppend(logTextView, printData("leftRotatedRndB", leftRotatedRndB));
            // Concatenate the RndA and rotated RndB byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            byte[] rndA_rndB = concatenate(rndA, leftRotatedRndB);
            if (verbose) writeToUiAppend(logTextView, printData("rndA_rndB", rndA_rndB));

            // Encrypt the bytes of the last step to get the challenge answer byte[] challengeAnswer = encrypt(rndA_rndB, defaultDESKey, IV);
            IV = getChallengeResponse.getData();
            writeToUiAppend(logTextView, printData("IV from challengeAnswer", IV));
            byte[] challengeAnswer = encryptDes(rndA_rndB, DES_KEY, IV);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswer", challengeAnswer));

            IV = Arrays.copyOfRange(challengeAnswer, 8, 16);
                /*
                    Build and send APDU with the answer. Basically wrap the challenge answer in the APDU.
                    The total size of apdu (for this scenario) is 22 bytes:
                    > 0x90 0xAF 0x00 0x00 0x10 [16 bytes challenge answer] 0x00
                */
            Response getChallengeResponse2 = sendData(isoDep, SW2_MORE_DATA, challengeAnswer);
            /*
            byte[] challengeAnswerAPDU = new byte[22];
            challengeAnswerAPDU[0] = (byte) 0x90; // CLS
            challengeAnswerAPDU[1] = (byte) 0xAF; // INS
            challengeAnswerAPDU[2] = (byte) 0x00; // p1
            challengeAnswerAPDU[3] = (byte) 0x00; // p2
            challengeAnswerAPDU[4] = (byte) 0x10; // data length: 16 bytes
            challengeAnswerAPDU[challengeAnswerAPDU.length - 1] = (byte) 0x00;
            System.arraycopy(challengeAnswer, 0, challengeAnswerAPDU, 5, challengeAnswer.length);

             */
            if (verbose) {
                writeToUiAppend(logTextView, printData("challengeAnswerCommand", getChallengeResponse2.getCommand()));
                writeToUiAppend(logTextView, printData("challengeAnswerResponse", getChallengeResponse2.getFullResponse()));
            }
            /*
             * Sending the APDU containing the challenge answer.
             * It is expected to be return 10 bytes [rndA from the Card] + 9100
             */
            //byte[] challengeAnswerResponse = isoDep.transceive(challengeAnswerAPDU);
            // response = channel.transmit(new CommandAPDU(challengeAnswerAPDU));
            /*
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResponse", challengeAnswerResponse));
            byte[] challengeAnswerResp = Arrays.copyOf(challengeAnswerResponse, getChallengeResponse.length - 2);
            if (verbose)
                writeToUiAppend(logTextView, printData("challengeAnswerResp", challengeAnswerResp));
*/
            /*
             * At this point, the challenge was processed by the card. The card decrypted the
             * rndA rotated it and sent it back.
             * Now we need to check if the RndA sent by the Card is valid.
             */// encrypted rndA from Card, returned in the last step byte[] encryptedRndAFromCard = response.getData();

            // Decrypt the rnd received from the Card.byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            //byte[] rotatedRndAFromCard = decrypt(encryptedRndAFromCard, defaultDESKey, IV);
            byte[] rotatedRndAFromCard = decryptDes(getChallengeResponse2.getData(), DES_KEY, IV);
            if (verbose)
                writeToUiAppend(logTextView, printData("rotatedRndAFromCard", rotatedRndAFromCard));

            // As the card rotated left the rndA,// we shall un-rotate the bytes in order to get compare it to our original rndA.byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            byte[] rndAFromCard = rotateRight(rotatedRndAFromCard);
            if (verbose) writeToUiAppend(logTextView, printData("rndAFromCard", rndAFromCard));
            writeToUiAppend(logTextView, "********** AUTH RESULT **********");
            //System.arraycopy(createApplicationResponse, 0, response, 0, createApplicationResponse.length);
            if (Arrays.equals(rndA, rndAFromCard)) {
                writeToUiAppend(logTextView, "Authenticated");
                return true;
            } else {
                writeToUiAppend(logTextView, "Authentication failed");
                return false;
                //System.err.println(" ### Authentication failed. ### ");
                //log("rndA:" + toHexString(rndA) + ", rndA from Card: " + toHexString(rndAFromCard));
            }
            //writeToUiAppend(logTextView, "********** AUTH RESULT END **********");
            //return false;
        } catch (Exception e) {
            //throw new RuntimeException(e);
            writeToUiAppend(logTextView, "authenticateDes transceive failed: " + e.getMessage());
            writeToUiAppend(logTextView, "authenticateDes transceive failed: " + Arrays.toString(e.getStackTrace()));
        }
        return false;
    }

    /**
     * section for DES encryption
     */

    private static byte[] decryptDes(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipherDes(Cipher.DECRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static byte[] encryptDes(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipherDes(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static Cipher getCipherDes(int mode, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        IvParameterSpec algorithmParamSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, algorithmParamSpec);
        return cipher;
    }

    /**
     * section for AES encryption
     */

    private static byte[] decryptAes(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipherAes(Cipher.DECRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static byte[] encryptAes(byte[] data, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = getCipherAes(Cipher.ENCRYPT_MODE, key, IV);
        return cipher.doFinal(data);
    }

    private static Cipher getCipherAes(int mode, byte[] key, byte[] IV) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec algorithmParamSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, algorithmParamSpec);
        return cipher;
    }

    private static byte[] rotateLeft(byte[] data) {
        byte[] rotated = new byte[data.length];
        rotated[data.length - 1] = data[0];
        for (int i = 0; i < data.length - 1; i++) {
            rotated[i] = data[i + 1];
        }
        return rotated;
    }

    private static byte[] rotateRight(byte[] data) {
        byte[] unrotated = new byte[data.length];
        for (int i = 1; i < data.length; i++) {
            unrotated[i] = data[i - 1];
        }
        unrotated[0] = data[data.length - 1];
        return unrotated;
    }

    private static byte[] concatenate(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];
        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }
        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }
        return concatenated;
    }



    /**
     * section for the sending of a command with or without parameters/data to a card
     */

    private Response sendData(IsoDep isoDep, byte command, byte[] parameters) {
        byte[] response;
        byte[] wrappedCommand = new byte[0];
        try {
            if (parameters == null) {
                wrappedCommand = wrapMessage(command);
            } else {
                wrappedCommand = wrapMessage(command, parameters);
            }
            Log.d(TAG, printData("wrappedCommand" , wrappedCommand));
            response = isoDep.transceive(wrappedCommand);
            if (response == null) {
                // either communication to the tag was lost or any other error was received
                writeToUiAppend(readResult, "ERROR: null response");
                return null;
            }
        } catch (TagLostException e) {
            // Log and return
            runOnUiThread(() -> {
                readResult.setText("ERROR: Tag lost exception or command not recognized " + e.getMessage());
            });
            return null;
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR: IOException " + e.getMessage());
            e.printStackTrace();
            return null;
        }
        Log.d(TAG, printData("response", response));
        return new Response(wrappedCommand, response);
    }

    private boolean checkResponse(TextView readResult, Response response) {
        if (response.getSw1() != SW1_OK) {
            writeToUiAppend(readResult, "The response of SW1 is not 0x91, aborted because found " + String.format("%02X", response.getSw1()));
            return false;
        }
        if ((response.getSw2() != SW2_OK) && (response.getSw2() != SW2_MORE_DATA)) {
            writeToUiAppend(readResult, "The response of SW2 is not 0x00 or 0xAF, aborted because found " + String.format("%02X", response.getSw2()));
            return false;
        }
        return true;
    }

    /**
     * section for wrapping a native command in ISO/IEC 7816-4 structure
     */

    public byte[] wrapMessage(byte command)  {
        return new byte[]{(byte) 0x90, command, 0x00, 0x00, 0x00};
    }

    public byte[] wrapMessage(byte command, byte[] parameters) {
        return wrapMessage(command, parameters, 0, parameters.length);
    }

    public byte[] wrapMessage(byte command, byte[] parameters, int offset, int length) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null && length > 0) {
            // actually no length if empty length
            stream.write(length);
            stream.write(parameters, offset, length);
        }
        stream.write((byte) 0x00);
        return stream.toByteArray();
    }



    /**
     * Determines whether the specified byte array starts with the specific bytes.
     *
     * @param array The array whose start is tested.
     * @param startBytes The byte array whose presence at the start of the array is tested.
     * @return 'true' when the array starts with the specified start bytes, 'false' otherwise.
     */
    private static boolean startsWith(byte[] array, byte[] startBytes) {
        if (array == null || startBytes == null || array.length < startBytes.length) {
            return false;
        }

        for (int i = 0; i < startBytes.length; i++) {
            if (array[i] != startBytes[i]) {
                return false;
            }
        }

        return true;
    }

    private static byte[] trim(byte[] bytes)
    {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
        {
            --i;
        }
        return Arrays.copyOf(bytes, i + 1);
    }

    // https://stackoverflow.com/a/51338700/8166854
    private byte[] selectApdu(byte[] aid) {
        byte[] commandApdu = new byte[6 + aid.length];
        commandApdu[0] = (byte) 0x00;  // CLA
        commandApdu[1] = (byte) 0xA4;  // INS
        commandApdu[2] = (byte) 0x04;  // P1
        commandApdu[3] = (byte) 0x00;  // P2
        commandApdu[4] = (byte) (aid.length & 0x0FF);       // Lc
        System.arraycopy(aid, 0, commandApdu, 5, aid.length);
        commandApdu[commandApdu.length - 1] = (byte) 0x00;  // Le
        return commandApdu;
    }

    public static List<byte[]> divideArray(byte[] source, int chunksize) {

        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    public static int byteArrayToInt(byte[] byteArray) {
        if (byteArray == null) {
            throw new IllegalArgumentException("Parameter \'byteArray\' cannot be null");
        } else {
            return byteArrayToInt(byteArray, 0, byteArray.length);
        }
    }

    public static int byteArrayToInt(byte[] byteArray, int startPos, int length) {
        if (byteArray == null) {
            throw new IllegalArgumentException("Parameter \'byteArray\' cannot be null");
        } else if (length > 0 && length <= 4) {
            if (startPos >= 0 && byteArray.length >= startPos + length) {
                int value = 0;

                for (int i = 0; i < length; ++i) {
                    value += (byteArray[startPos + i] & 255) << 8 * (length - i - 1);
                }

                return value;
            } else {
                throw new IllegalArgumentException("Length or startPos not valid");
            }
        } else {
            throw new IllegalArgumentException("Length must be between 1 and 4. Length = " + length);
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private String getDec(byte[] bytes) {
        long result = 0;
        long factor = 1;
        for (int i = 0; i < bytes.length; ++i) {
            long value = bytes[i] & 0xffl;
            result += value * factor;
            factor *= 256l;
        }
        return result + "";
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public String printData(String dataName, byte[] data) {
        int dataLength;
        String dataString = "";
        if (data == null) {
            dataLength = 0;
            dataString = "IS NULL";
        } else {
            dataLength = data.length;
            dataString = Utils.bytesToHex(data);
        }
        StringBuilder sb = new StringBuilder();
        sb
                .append(dataName)
                .append(" length: ")
                .append(dataLength)
                .append(" data: ")
                .append(dataString);
        return sb.toString();
    }

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = textView.getText().toString() + "\n" + message;
            textView.setText(newString);
        });
    }

    private void writeToUiAppendReverse(TextView textView, String message) {
        runOnUiThread(() -> {
            String newString = message + "\n" + textView.getText().toString();
            textView.setText(newString);
        });
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    private byte[] getFastTagDataRange(NfcA nfcA, int fromPage, int toPage) {
        byte[] response;
        byte[] command = new byte[]{
                (byte) 0x3A,  // FAST_READ
                (byte) (fromPage & 0x0ff),
                (byte) (toPage & 0x0ff),
        };
        try {
            response = nfcA.transceive(command); // response should be 16 bytes = 4 pages
            if (response == null) {
                // either communication to the tag was lost or a NACK was received
                writeToUiAppend(readResult, "ERROR on reading page");
                return null;
            } else if ((response.length == 1) && ((response[0] & 0x00A) != 0x00A)) {
                // NACK response according to Digital Protocol/T2TOP
                writeToUiAppend(readResult, "ERROR NACK received");
                // Log and return
                return null;
            } else {
                // success: response contains ACK or actual data
            }
        } catch (TagLostException e) {
            // Log and return
            writeToUiAppend(readResult, "ERROR Tag lost exception");
            return null;
        } catch (IOException e) {
            writeToUiAppend(readResult, "ERROR IOException: " + e);
            e.printStackTrace();
            return null;
        }
        return response;
    }

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    private void exportDumpMail() {
        if (dumpExportString.isEmpty()) {
            writeToUiToast("Scan a tag first before sending emails :-)");
            return;
        }
        String subject = "Dump NFC-Tag " + tagTypeString + " UID: " + tagIdString;
        String body = dumpExportString;
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        intent.putExtra(Intent.EXTRA_TEXT, body);
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        }
    }

    private void exportDumpFile() {
        if (dumpExportString.isEmpty()) {
            writeToUiToast("Scan a tag first before writing files :-)");
            return;
        }
        verifyPermissionsWriteString();
    }

    // section external storage permission check
    private void verifyPermissionsWriteString() {
        String[] permissions = {Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE};
        if (ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[0]) == PackageManager.PERMISSION_GRANTED
                && ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[1]) == PackageManager.PERMISSION_GRANTED) {
            writeStringToExternalSharedStorage();
        } else {
            ActivityCompat.requestPermissions(this,
                    permissions,
                    REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE);
        }
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        //boolean pickerInitialUri = false;
        //intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = tagTypeString + "_" + tagIdString + ".txt";
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writng the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        fileSaverActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> fileSaverActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = dumpExportString;
                                writeTextToUri(uri, fileContent);
                                String message = "file written to external shared storage: " + uri.toString();
                                writeToUiToast("file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(contextSave.getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            if (!mNfcAdapter.isEnabled())
                showWirelessSettings();

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mExportMail = menu.findItem(R.id.action_export_mail);
        mExportMail.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                exportDumpMail();
                return false;
            }
        });

        MenuItem mExportFile = menu.findItem(R.id.action_export_file);
        mExportFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                exportDumpFile();
                return false;
            }
        });
        return super.onCreateOptionsMenu(menu);
    }

}