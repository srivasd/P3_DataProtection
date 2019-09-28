package com.company;

import java.io.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;


public class RSALibrary {

    // String to hold name of the encryption algorithm.
    public final String ALGORITHM = "RSA";

    //String to hold the name of the private key file.
    public final String PRIVATE_KEY_FILE = "./private.key";

    // String to hold name of the public key file.
    public final String PUBLIC_KEY_FILE = "./public.key";

    /***********************************************************************************/
    /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
    /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
    /* Throws IOException */
    /***********************************************************************************/
    public void generateKeys() throws IOException {

        try {

            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);

            // TO-DO: Use KeyGen to generate a public and a private key
            KeyPair keyPair = keyGen.generateKeyPair();

            // TO-DO: store the public key in the file PUBLIC_KEY_FILE
            Key keyPub = keyPair.getPublic();

            writeKey(PUBLIC_KEY_FILE, keyPub);

            // TO-DO: store the private key in the file PRIVATE_KEY_FILE
            Key keyPriv = keyPair.getPrivate();

            writeKey(PRIVATE_KEY_FILE, keyPriv);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    public void generateKeysPrivateEncrypted() throws Exception {

        try {

            SymmetricCipher symmetricCipher = new SymmetricCipher();

            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024);

            // TO-DO: Use KeyGen to generate a public and a private key
            KeyPair keyPair = keyGen.generateKeyPair();

            // TO-DO: store the public key in the file PUBLIC_KEY_FILE
            Key keyPub = keyPair.getPublic();

            // TO-DO: store the private key in the file PRIVATE_KEY_FILE
            Key keyPriv = keyPair.getPrivate();

            String passphrase = "";

            while (passphrase.length() != 16) {
                System.out.print("Type a passphrase you want to use to encrypt the private key (16 character length): ");
                Scanner s = new Scanner(System.in);
                passphrase = s.nextLine();
            }

            writeKey(PUBLIC_KEY_FILE, keyPub);

            byte[] result_g = symmetricCipher.encryptCBC(convertToBytes(keyPriv), passphrase.getBytes());

            try (FileOutputStream stream = new FileOutputStream(PRIVATE_KEY_FILE)) {
                stream.write(result_g);
            }

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception: " + e.getMessage());
            System.exit(-1);
        }
    }


    private void writeKey (String outputPath, Key key) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(outputPath);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(key);
        objectOutputStream.close();
    }

    public PublicKey readPublicKey (String inputPath) throws IOException, ClassNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(inputPath);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        Object keyObject = objectInputStream.readObject();
        PublicKey key = (PublicKey) keyObject;
        objectInputStream.close();
        return key;
    }

    public PrivateKey readPrivateKey (String inputPath) throws IOException, ClassNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(inputPath);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        Object keyObject = objectInputStream.readObject();
        PrivateKey key = (PrivateKey) keyObject;
        objectInputStream.close();
        return key;
    }

    /***********************************************************************************/
    /* Encrypts a plaintext using an RSA public key. */
    /* Arguments: the plaintext and the RSA public key */
    /* Returns a byte array with the ciphertext */
    /***********************************************************************************/
    public byte[] encrypt(byte[] plaintext, PublicKey key) {

        byte[] ciphertext = null;

        try {

            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // TO-DO: initialize the cipher object and use it to encrypt the plaintext
            cipher.init(Cipher.ENCRYPT_MODE, key);

            ciphertext = cipher.doFinal(plaintext);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ciphertext;
    }


    /***********************************************************************************/
    /* Decrypts a ciphertext using an RSA private key. */
    /* Arguments: the ciphertext and the RSA private key */
    /* Returns a byte array with the plaintext */
    /***********************************************************************************/
    public byte[] decrypt(byte[] ciphertext, PrivateKey key) {

        byte[] plaintext = null;

        try {
            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // TO-DO: initialize the cipher object and use it to decrypt the ciphertext
            cipher.init(Cipher.DECRYPT_MODE, key);

            plaintext = cipher.doFinal(ciphertext);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return plaintext;
    }

    /***********************************************************************************/
    /* Signs a plaintext using an RSA private key. */
    /* Arguments: the plaintext and the RSA private key */
    /* Returns a byte array with the signature */
    /***********************************************************************************/
    public byte[] sign(byte[] plaintext, PrivateKey key) {

        byte[] signedInfo = null;

        try {

            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            // TO-DO: initialize the signature oject with the private key
            signature.initSign(key);

            // TO-DO: set plaintext as the bytes to be signed
            signature.update(plaintext);

            // TO-DO: sign the plaintext and obtain the signature (signedInfo)
            signedInfo = signature.sign();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return signedInfo;
    }

    /***********************************************************************************/
    /* Verifies a signature over a plaintext */
	/* Arguments: the plaintext, the signature to be verified (signed)
  /* and the RSA public key */
    /* Returns TRUE if the signature was verified, false if not */
    /***********************************************************************************/
    public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

        boolean result = false;

        try {

            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            // TO-DO: initialize the signature oject with the public key
            signature.initVerify(key);

            // TO-DO: set plaintext as the bytes to be veryfied
            signature.update(plaintext);

            // TO-DO: verify the signature (signed). Store the outcome in the boolean result
            result = signature.verify(signed);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return result;
    }

    private byte[] convertToBytes(Object object) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(object);
            return bos.toByteArray();
        }
    }

    private Object convertFromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInput in = new ObjectInputStream(bis)) {
            return in.readObject();
        }
    }

}

