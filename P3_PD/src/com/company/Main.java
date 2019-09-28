package com.company;
import java.io.*;
import java.security.*;
import java.util.Random;
import java.util.Scanner;

public class Main {

    public static void main(String[] args){
        // write your code here
        SymmetricCipher symmetricCipher = new SymmetricCipher();

        //Comment this before generating jar
        //args = new String[1];
        //args[0] = "g";
        //args[1] = "test.txt";
        //args[2] = "testOutput.txt";

        System.out.println("Application for secure storage of files using [AES-128 CBC PKCS#5] and [RSA-128]");

        if (args.length == 0) {
            System.out.println("Command not found.");
            System.out.println("USAGE: java -jar P3_PD_jar command [sourceFile] [destinationFile]");
        } else {

            String command = args[0];
            RSALibrary rsa = new RSALibrary();

            if (command.equals("g") || command.equals("-g")) {
                //Generamos clave privada y pública
                try {
                    rsa.generateKeysPrivateEncrypted();
                    System.out.println("Keys generated in the current directory");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            else if(command.equals("e") || command.equals("-e")) {

                if(args.length == 1) {
                    System.out.println("The input and output files have not been indicated");
                } else if(args.length == 2 || args.length == 3) {
                    File inputFile = new File(args[1]);
                    //We check if the inputFile exists
                    if (inputFile.exists()) {
                        //Leemos el fichero de entrada
                        byte[] inputFileBytes = readFileToByteArray(inputFile);

                        byte[] sessionKey = new byte[16];
                        try {
                            SecureRandom.getInstanceStrong().nextBytes(sessionKey);
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }

                        try {

                            //Get the file and the session key encrypted
                            byte[] ciphertextBytes = symmetricCipher.encryptCBC(inputFileBytes, sessionKey);
                            PublicKey publicKey = rsa.readPublicKey(rsa.PUBLIC_KEY_FILE);
                            byte[] cipheredSessionKey = rsa.encrypt(sessionKey, publicKey);
                            int aLen = ciphertextBytes.length;
                            int bLen = cipheredSessionKey.length;
                            byte[] fileToHash = new byte[aLen + bLen];
                            System.arraycopy(ciphertextBytes, 0, fileToHash, 0, aLen);
                            System.arraycopy(cipheredSessionKey, 0, fileToHash, aLen, bLen);

                            //Get the private Key
                            String passphrase = "";

                            while (passphrase.length() != 16) {
                                System.out.print("Type the passphrase you used to encrypt the private key (16 character length): ");
                                Scanner s = new Scanner(System.in);
                                passphrase = s.nextLine();
                            }

                            byte[] privateKeyBytesEnc = readFileToByteArray(new File(rsa.PRIVATE_KEY_FILE));
                            byte[] privateKeyBytes = symmetricCipher.decryptCBC(privateKeyBytesEnc, passphrase.getBytes());
                            // *********CONTROLAR AQUÍ EL CASO EN EL QUE SE META DE MANERA INCORRECTA AL PASSPHRASE*********
                            Object privateKeyObject = convertFromBytes(privateKeyBytes);
                            PrivateKey privateKey = (PrivateKey) privateKeyObject;

                            //Firmamos el contenido del fichero y la clave de sesion
                            byte[] sign = rsa.sign(fileToHash, privateKey);

                            //Concatenamos al resto
                            int cLen = fileToHash.length;
                            int dLen = sign.length;
                            byte[] finalFile = new byte[cLen + dLen];
                            System.arraycopy(fileToHash, 0, finalFile, 0, cLen);
                            System.arraycopy(sign, 0, finalFile, cLen, dLen);

                            //Escribimos en el fichero
                            if (args.length == 2) {
                                //Set the name of the encrypted file if it is not indicated in the command
                                System.out.println(args[1]);
                                String[] pathSplit = args[1].split("\\.");
                                String outputPath = "fileEncrypted." + pathSplit[pathSplit.length - 1];
                                File outputFile = new File(outputPath);
                                writeBytesToFile(finalFile, outputFile);
                            } else {
                                //Set the name of the encrypted file if it is indicated in the command
                                File outputFile = new File(args[2]);
                                writeBytesToFile(finalFile, outputFile);
                            }

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        System.out.println("The input file does not exist. Try again.");
                    }
                }
            }
            else if(command.equals("d") || command.equals("-d")) {

                //Casos erroneos TODO:

                if(args.length == 3) {
                    File inputFile = new File(args[3]);
                    if(!inputFile.exists())
                        System.out.println("The source file: " + args[3] + " does not exist");
                    else {
                        //Leer fichero
                        byte[] fileToBytes = readFileToByteArray(new File(args[3]));

                        //Dividir fichero

                        //Signature -> 1024

                        //verify signature

                        //key->

                        //Decrypt key

                        //Decrypt rest of the file(text) with decrypted key

                        //Guardar texto en claro

                    }

                }

            }
            else {
                System.out.println("Not valid command found (g,e,d)");
            }
        }
    }

    // Method which reads a file and returns a byte array
    private static byte[] readFileToByteArray(File file){
        FileInputStream fis = null;
        byte[] bArray = new byte[(int) file.length()];
        try{
            fis = new FileInputStream(file);
            fis.read(bArray);
            fis.close();

        }catch(IOException ioExp){
            ioExp.printStackTrace();
        }
        return bArray;
    }

    // Method which converts object to bytes
    private static byte[] convertToBytes(Object object) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(object);
            return bos.toByteArray();
        }
    }

    // Method which converts bytes to object
    private static Object convertFromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInput in = new ObjectInputStream(bis)) {
            return in.readObject();
        }
    }

    // Method which write the bytes into a file
    private static void writeBytesToFile(byte[] bytes, File file)
    {
        try {

            OutputStream os = new FileOutputStream(file);
            os.write(bytes);
            System.out.println("Output file encrypted generated successfully");
            os.close();
        }

        catch (Exception e) {
            System.out.println("Exception: " + e);
        }
    }
}