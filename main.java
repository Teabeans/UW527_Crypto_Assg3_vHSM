//-------|---------|---------|---------|---------|---------|---------|---------|
//
// UW CSS 527 - Assg3 - KEKs
// main.java
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-----------------------------------------------------------------------------|
// Authorship
//-----------------------------------------------------------------------------|
//
// Tim Lum
// twhlum@gmail.com
//
// Created:  2020.02.24
// Modified: 2020.02.25
// For the University of Washington Bothell, CSS 527
// Winter 2020, Masters in Cybersecurity Engineering (MCSE)
//

//-----------------------------------------------------------------------------|
// File Description
//-----------------------------------------------------------------------------|
//
// TODO

//-----------------------------------------------------------------------------|
// Package Files
//-----------------------------------------------------------------------------|
//
// See README.md

//-----------------------------------------------------------------------------|
// Useage
//-----------------------------------------------------------------------------|
//
// Compile with:
// javac Main.java && java Main
//
// Note: Requires Java SDK installed to the Linux environment. Install with:
// $ sudo apt-get update
// $ sudo apt-get install openjdk-8-jdk

//-------|---------|---------|---------|---------|---------|---------|---------|
//
//       INCLUDES
//
//-------|---------|---------|---------|---------|---------|---------|---------|

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.awt.Dimension;

import java.io.Console; // For silent password read
import java.io.File;                  // For file operations
import java.io.FileNotFoundException; // For file exception

import java.io.IOException;    // For buffered writer
import java.io.BufferedWriter; // For buffered writing
import java.io.FileWriter;     // For buffered writing

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;          // For RSA keypair
import java.security.KeyPairGenerator; // For RSA keypair generator
import java.security.KeyFactory; // For key generation from byte array
import java.security.spec.PKCS8EncodedKeySpec; // For PKCS8 key generation from byte array
import java.security.spec.X509EncodedKeySpec; // For X509 key generation from byte array

import java.security.SecureRandom; // For random number from seed
import java.security.NoSuchAlgorithmException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest; // For cipher.init
import java.util.Base64; // For base 64 encoding of keys
import java.util.Arrays; // For AES
import javax.crypto.Cipher; // For AES
import javax.crypto.spec.SecretKeySpec; // For AES
import java.security.Signature; // For signatures

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Iterator; // For iterators
import java.util.Scanner; // For user inputs
import java.util.HashSet; // For hashsets
import java.util.LinkedList; // For linked lists
import java.util.Date; // For timestamps
import java.text.SimpleDateFormat; // For formatting timestamp
import java.time.Instant;
import javax.swing.*; 
import java.awt.*;
import java.awt.event.*;

public class Main {

// -------|---------|---------|---------|---------|---------|---------|---------|
//
// GLOBAL CONSTANTS
//
// -------|---------|---------|---------|---------|---------|---------|---------|

  static boolean DEBUG = true;
  static boolean FASTMODE = true;
  static boolean LOGGED_IN = false;
  static String WHO_AM_I = null;
  static String MY_SECRET = null;
  static final int NUM_TESTS = 1000000;
  static final int LOOKAHEAD = 100;
  static final String KVC_PASSPHRASE  = "test";
  static final String SIGNATURE       = "MyNameIsInigoMontoyaYouKilledMyFatherPrepareToDie";
  static final String HSM_SECRET      = "hsmsecret.txt";
  static final String USERDB_IN       = "user_passwordhash.txt";
  static final String USERDB_OUT      = "user_passwordhash_output.txt";
  static final String KEY_KEKDB_IN    = "keyid_KEK.txt";
  static final String KEY_KEKDB_OUT   = "keyid_KEK_output.txt";
  static final String PUB_KEYSDB_IN   = "publickey_keyID.txt";
  static final String PUB_KEYSDB_OUT  = "publickey_keyID_output.txt";
  static final String PRIV_KEYSDB_IN  = "privatekey_keyID.txt";
  static final String PRIV_KEYSDB_OUT = "privatekey_keyID_output.txt";
  static final String USER_KEYID_IN   = "user_KeyIDs.txt";
  static final String USER_KEYID_OUT  = "user_KeyIDs_output.txt";
  static final String KEYID_KVCDB_IN  = "keyid_KVC.txt";
  static final String KEYID_KVCDB_OUT = "keyid_KVC_output.txt";

// -------|---------|---------|---------|---------|---------|---------|---------|
//
// PROGRAM DRIVER
//
// -------|---------|---------|---------|---------|---------|---------|---------|

  // NOTE:
  // Initial driver version for testing out each of the methods. Will refactor
  // into usable form.

  public static void main(String[] args) throws Exception {
//-------|---------|---------|---------|
// ACQUIRE PROGRAM ROLE
//-------|---------|---------|---------|  
    String role = args[0];
    if (!role.equals("SERVER") && !role.equals("CLIENT") && !role.equals("TEST")) {
      System.out.println( "Improper argument passed (" + args[0] + "). Halting..." );
      System.exit(0);
    }
    else {
      if (DEBUG) {
        System.out.println( "My role is: " + role );
        System.out.println();
      }
    }

// -------|---------|---------|---------|
// TEST
// -------|---------|---------|---------|
    if( role.equals( "TEST" ) ) {
      System.out.println( "TEST SUITE ACTIVATED" );
      HashSet userDB = loadFromFile( "user_passwordhash.txt" );

      String[] testUser = new String[2];
      testUser[0] = "InigoMontoya";
      String password = "YouKilledMyFather";

      try {
        testUser[1] = hash_SHA256( password );
      }
        catch (Exception e) {
        e.printStackTrace(System.out);
      }

      boolean addResult = addPair( userDB, testUser );
      if( DEBUG ) {
        System.out.println( "AddPair result 1: " + addResult );
      }
      addResult = addPair( userDB, testUser );
      if( DEBUG ) {
        System.out.println( "AddPair result 2: " + addResult );
      }

      renderHashSet( userDB );

      writeToFile( userDB, "user_passwordhash_output.txt" );
    } // Closing TEST ROLE

// -------|---------|---------|---------|
// SERVER
// -------|---------|---------|---------|
    else if( role.equals( "SERVER" ) ) {
      System.out.println( "SERVER SUITE ACTIVATED" );
      // Load known information from the databases
      HashSet<String[]> userDB   = loadFromFile( USERDB_IN      );
      HashSet<String[]> idKEKDB  = loadFromFile( KEY_KEKDB_IN   );
      HashSet<String[]> pubKeys  = loadFromFile( PUB_KEYSDB_IN  );
      HashSet<String[]> privKeys = loadFromFile( PRIV_KEYSDB_IN );
      HashSet<String[]> keyIDs   = loadFromFile( USER_KEYID_IN  );
      HashSet<String[]> kvcDB    = loadFromFile( KEYID_KVCDB_IN );
      MY_SECRET = loadSecret( HSM_SECRET );

      // Auto-login
      if( FASTMODE ) {
        LOGGED_IN = true;
        WHO_AM_I = "teabeans";
      }

      System.out.println();
      System.out.println( "WELCOME TO THE VIRTUAL HSM:" );

      Scanner userInput = new Scanner(System.in);
      boolean isRunning = true;
      while( isRunning ) {
        renderOptions();
        String choice = userInput.next();

        // -------|---------|---------|---------|
        // NEW USER ACCOUNT CASE
        // -------|---------|---------|---------|
        if( choice.equals( "N" ) ) {
          System.out.print( "NEW USERNAME: " );
          String username = userInput.next();
          // Check if user is already in the database
          if( doesContainKey( userDB, username ) ) {
            System.out.println( "Username unavailable. Aborting..." );
            break;
          }
          System.out.println( "Username available! Select password." );
          System.out.print( "PASSWORD: ");
          String password = new String( System.console( ).readPassword( ) );
          String hash = null;
          try {
            hash = hash_SHA256( password );
          }
          catch (Exception e) {
            e.printStackTrace(System.out);
          }
          if( DEBUG ) {
            System.out.println( "Password: " + password + " => " + hash );
          }

          String[] pair = new String[2];
          pair[0] = username;
          pair[1] = hash;
          boolean addResult = addPair( userDB, pair );
          if( DEBUG ) {
            System.out.println( "Add result: " + addResult );
            renderHashSet( userDB );
            System.out.println();
          }
        } // Closing new user account case

        // -------|---------|---------|---------|
        // LOGIN CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "L" ) ) {
          System.out.print( "USERNAME: " );
          String username = userInput.next();
          System.out.print( "PASSWORD: " );
          String password = new String( System.console( ).readPassword( ) );
          // -------|---------|
          // Hash the password
          // -------|---------|
          String hash = null;
          try {
            hash = hash_SHA256( password );
          }
          catch (Exception e) {
            e.printStackTrace(System.out);
          }
          if( DEBUG ) {
            System.out.println( "Password: " + password + " => " + hash );
          }
          // -------|---------|
          // Check credentials against database
          // -------|---------|
          if( getValue( userDB, username ).equals( hash ) ) {
            System.out.println( "Username:Password accepted. Login successful." );
            System.out.println();
            LOGGED_IN = true;
            WHO_AM_I = username;
          }
          else {
            System.out.println( "Username:Password denied. Logging out." );
            System.out.println();
            LOGGED_IN = false;
            WHO_AM_I = null;
          }

        } // Closing login case

        // -------|---------|---------|---------|
        // REPORT CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "R" ) ) {
          System.out.println( "Reporting state of vHSM..." );
          System.out.println( "Logged in   : " + LOGGED_IN );
          System.out.println( "Current User: " + WHO_AM_I  );
          System.out.println( "vHSM Secret : " + MY_SECRET );
          System.out.println();

          System.out.println( "USERS:" );
          renderHashSet( userDB );
          System.out.println();

          System.out.println( "KEY IDS:" );
          renderHashSet( keyIDs );
          System.out.println();

          System.out.println( "KEY ENCRYPTION KEYS (KEKS):" );
          renderHashSet( idKEKDB );
          System.out.println();

          System.out.println( "KEY VERIFICATION CODES (KVCS):" );
          renderHashSet( kvcDB );
          System.out.println();

          System.out.println( "PUBLIC KEYS:" );
          renderHashSet( pubKeys );
          System.out.println();

          System.out.println( "PRIVATE KEYS:" );
          renderHashSet( privKeys );
          System.out.println();
        } // Closing HSM Report case

        // -------|---------|---------|---------|
        // CREATE KEY CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "C" ) && LOGGED_IN ) {
          // -------|---------|
          // Acquire key password
          // -------|---------|
          System.out.print( "KEY PASSWORD: " );
          String keypass = null;
          if( FASTMODE ) {
            keypass = "foobarbaz";
          }
          else {
           keypass = new String( System.console( ).readPassword( ) );
          }

          if( DEBUG ) {
            System.out.println( "Input acquired:" );
            System.out.println( "  USER: " + WHO_AM_I );
            System.out.println( "  PASS: " + keypass );
          }
          // -------|---------|
          // Calculate Key ID
          // -------|---------|
          // In form: 'USERNAME SHA256HASHOFPASSWORD'
          String keyID = calcKeyID( WHO_AM_I, keypass );
          // Trim the username back off the keyID
          String keyHash = keyID.replaceFirst( (WHO_AM_I + " "), "" );

          // -------|---------|
          // Pre-existing keypassword check
          // -------|---------|
          if( doesContainKeyValPair( keyIDs, WHO_AM_I, keyHash ) ) {
            System.out.println( "Pre-existing Key ID found. Aborting..." );
            System.out.println();
            continue; // Jump back to top of while loop
          }
          else {
            if( DEBUG ) {
              System.out.println( "Pre-existing Key ID not found. Adding to keyID database..." );
            }
            // -------|---------|
            // Not found, so add ID to list of known keys
            // -------|---------|
            String[] userKeyPair = new String[2];
            userKeyPair[0] = WHO_AM_I;
            userKeyPair[1] = keyHash;
            addPair( keyIDs, userKeyPair );
          }

          // -------|---------|
          // RSA generate Public and Private keys
          // -------|---------|
          KeyPair kp = generateKeyPair( keypass );

          // KeyPair kp = null;
          Key pub = kp.getPublic( );
          Key pvt = kp.getPrivate( );

          // Convert to Base64 representation
          Base64.Encoder encoder = Base64.getEncoder( );
          String pubKey_64 = encoder.encodeToString( pub.getEncoded( ) );
          String pvtKey_64 = encoder.encodeToString( pvt.getEncoded( ) );

          if( DEBUG ) {
            System.out.println( "Public key:" );
            System.out.println( "  Format: " + pub.getFormat( ) );
            System.out.println( "  Value : " + pub.getEncoded( ) );
            System.out.println( "  Base64: " + pubKey_64 );
            
            System.out.println( "Private key: " + pvt.getFormat( ) );
            System.out.println( "  Format: " + pvt.getFormat( ) );
            System.out.println( "  Value : " + pvt.getEncoded( ) );
            System.out.println( "  Base64: " + pvtKey_64 );
          }

          // -------|---------|
          // Calculate Key Encryption Key (KEK)
          // -------|---------|
          // KEK == (HSMSecretKey) XOR (SHA256(KeyPassword))
          String sha256KeyPass = null;
          try {
            sha256KeyPass = hash_SHA256( keypass );
          }
          catch( Exception e ) {
            e.printStackTrace( System.out );
          }

          if( DEBUG ) {
            System.out.println( keypass + " => " + sha256KeyPass );
            System.out.println( "Attempting XOR: " );
            System.out.println( "  " + sha256KeyPass );
            System.out.println( "  " + MY_SECRET );
          }

          String keyEncryptionKey = xorHex( sha256KeyPass, MY_SECRET );

          if( DEBUG ) {
            System.out.println( "Hexadecimal XOR Result (KEK): " );
            System.out.println( "  " + keyEncryptionKey );
            System.out.println();
          }

          // -------|---------|
          // Store encrypted KEK to server
          // -------|---------|
          String[] idAndKEK = new String[2];
          idAndKEK[0] = WHO_AM_I + ":" + keyHash; // Key ID
          idAndKEK[1] = keyEncryptionKey;
          addPair( idKEKDB, idAndKEK );

          // -------|---------|
          // Store unencrypted pubKey to server
          // -------|---------|
          String[] idAndPubkey = new String[2];
          idAndPubkey[0] = WHO_AM_I + ":" + keyHash;
          idAndPubkey[1] = pubKey_64;
          addPair( pubKeys, idAndPubkey);

          // -------|---------|
          // Encrypt RSA Private with AES
          // -------|---------|                  plaintext  key
          String pvtKey_encrypted = encrypt_AES( pvtKey_64, keyEncryptionKey );

          // -------|---------|
          // Calculate Key Verification Code (KVC)
          // -------|---------|
          String plaintext = KVC_PASSPHRASE;
          String kekVerificationCode = encrypt_AES( plaintext, keyEncryptionKey );

          // Store the KVC to the database
          String[] idAndKVC = new String[2];
          idAndKVC[0] = WHO_AM_I + ":" + keyHash;
          idAndKVC[1] = kekVerificationCode;
          addPair( kvcDB, idAndKVC );

          if( DEBUG ) {
            System.out.println( "Plaintext : " + plaintext );
            System.out.println( "Ciphertext: " + kekVerificationCode );
            String roundTrip = decrypt_AES( kekVerificationCode, keyEncryptionKey );
            System.out.println( "Roundtrip : " + roundTrip );
            System.out.println();
          }

          if( DEBUG ) {
            System.out.println( "Testing roundtrip of RSA private key: " );
            System.out.println( "  Pre : " + pvtKey_64 );
            System.out.println( "  Mid : " + pvtKey_encrypted );
            String pvtKey_roundtrip = decrypt_AES( pvtKey_encrypted, keyEncryptionKey );
            System.out.println( "  Post: " + pvtKey_roundtrip );
            System.out.println();
          }

          // -------|---------|
          // Secure Private key in the HSM DB
          // -------|---------|
          if( DEBUG ) {
            System.out.println( "Ready to secure key to database:" );
            System.out.println( "  User             : " + WHO_AM_I            );
            System.out.println( "  KeyID            : " + keyID               );
            System.out.println( "  RSAPub           : " + pub.getEncoded( )   );
            System.out.println( "  RSAPriv          : " + pvt.getEncoded( )   );
            System.out.println( "  KEK              : " + keyEncryptionKey    );
            System.out.println( "  RSAPriv_Encrypted: " + pvtKey_encrypted    );
            System.out.println( "  KVC              : " + kekVerificationCode );
            System.out.println();
          }

          // -------|---------|
          // Store encrypted privKey to server
          // -------|---------|
          String[] idAndPrivkey = new String[2];
          idAndPrivkey[0] = WHO_AM_I + ":" + keyHash;
          idAndPrivkey[1] = pvtKey_encrypted;
          addPair( privKeys, idAndPrivkey);

        } // Closing Key Creation case

        // -------|---------|---------|---------|
        // ENCRYPT CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "E" ) && LOGGED_IN ) {
          System.out.println( "Encryption with PRIVATE key selected (authenticity, no confidentiality)" );

          // -------|---------|
          // Check if User has Keys
          // -------|---------|
          int keyCount = countByKey( keyIDs, WHO_AM_I );
          if( keyCount == 0 ) {
            System.out.println( "No keys registered to you. Please create a key before encrypting." );
            System.out.println();
            continue;
          }
          if( DEBUG ) {
            System.out.println( "Keys found! (" + keyCount + ")" );
          }
          // -------|---------|
          // Prompt user for key selection
          // -------|---------|
          System.out.print( "Enter key password to encrypt with: " );
          String identifier = null;
          if( FASTMODE ) {
            identifier = "foobarbaz";
          }
          else {
            identifier = new String( System.console( ).readPassword( ) );
          }
          // Calculate hash
          String hashLookup = null;
          try {
            hashLookup = hash_SHA256( identifier );
          }
          catch( Exception e ) {
            e.printStackTrace( System.out );
          }

          // -------|---------|
          // Attempt to locate user-specified key
          // -------|---------|
          if( DEBUG ) {
            System.out.println( "Looking up: " + hashLookup );
          }
          boolean didFind = doesContainKeyValPair( keyIDs, WHO_AM_I, hashLookup );
          String userPlusKeyID = null;
          if( didFind ) {
            System.out.println( "Key ID found! Concatenating..." );
            userPlusKeyID = WHO_AM_I + ":" + hashLookup;
            if( DEBUG ) {
              System.out.println( "Concatenation complete: " + userPlusKeyID );
            }
          }
          else {
            System.out.println( "Key not found. Aborting..." );
            System.out.println();
            continue;
          }
          // -------|---------|
          // Acquire Plaintext
          // -------|---------|
          String fileInput = "plaintext.txt";
          System.out.print( "Enter text to encrypt or leave blank to read from 'plaintext.txt': " );
          String plaintext = null;
          if( FASTMODE ) {
            plaintext = "";
            System.out.println( fileInput );
          }
          else {
            plaintext = userInput.next();
          }
          // If the user provides no input, read in from file
          if( plaintext.equals("") ) {
            plaintext = readFile( fileInput );
          }

          if( DEBUG ) {
            System.out.println( "Plaintext received: " );
            System.out.println( plaintext );
          }

          // -------|---------|
          // Acquire Key using lookup
          // -------|---------|
          String kekFromDB = getValue( idKEKDB,  userPlusKeyID );
          String kvcFromDB = getValue( kvcDB,    userPlusKeyID );
          String keyFromDB = getValue( privKeys, userPlusKeyID );

          if( DEBUG ) {
            System.out.println( "KVC and Encrypted Key acquired: " );
            System.out.println( "KVC: ");
            System.out.println( kvcFromDB );
            System.out.println();
            System.out.println( "Private Key (Encrypted): ");
            System.out.println( keyFromDB );
            System.out.println();
          }

          // -------|---------|
          // Confirm KVC
          // -------|---------|
          boolean kvcResult = confirmKVC( kvcFromDB, KVC_PASSPHRASE, kekFromDB );
          if( kvcResult == false ) {
            System.out.println( "Key Verification Code comparison failed. Aborting..." );
            continue;
          }
          else {
            System.out.println( "Key Verification Code comparison success! Decrypting key..." );
          }

          // -------|---------|
          // Decryption of private key
          // -------|---------|
          String pvtKey_decrypted = decrypt_AES( keyFromDB, kekFromDB );
          if( DEBUG ) {
            System.out.println( "Key decryption attempted. Result: " );
            System.out.println( pvtKey_decrypted );
            System.out.println();
          }

          // -------|---------|
          // Convert to key object
          // -------|---------|
          // Decode the base64-encoded string
          byte[] decodedKey = Base64.getDecoder( ).decode( pvtKey_decrypted );
          if( DEBUG ) {
            System.out.println( "Base64 Decoded:" );
            for( int i = 0 ; i < 100 ; i++ ) {
              System.out.print( decodedKey[i] );
            }
            System.out.println( "..." );
          }
          // For public:
          // PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
          // For private:
          PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec( decodedKey ));

          if( DEBUG ) {
            // Convert to Base64 representation
            Base64.Encoder encoder = Base64.getEncoder( );
            String privateKeyCheck = encoder.encodeToString( privateKey.getEncoded( ) );
            System.out.println( "Private key: " + privateKey.getFormat( ) );
            System.out.println( "  Format: " + privateKey.getFormat( ) );
            System.out.println( "  Value : " + privateKey.getEncoded( ) );
            System.out.println( "  Base64: " + privateKeyCheck );
          }

          // -------|---------|
          // Encrypt plaintext
          // -------|---------|
          //Encrypt with PRIVATE
          String encryptedText = encrypt_RSA( plaintext, privateKey );
          if( DEBUG ) {
            System.out.println( "Encryption complete: " );
            System.out.println( "Plaintext: " );
            System.out.println( plaintext );
            System.out.println( "Ciphertext: " );
            System.out.println( encryptedText );
            System.out.println();

          }

          // -------|---------|
          // Decrypt ciphertext check
          // -------|---------|
          // Get public key from DB
          keyFromDB = getValue( pubKeys, userPlusKeyID );
          byte[] pubKeySeed = Base64.getDecoder( ).decode( keyFromDB );
          PublicKey publicKey = KeyFactory.getInstance( "RSA" ).generatePublic( new X509EncodedKeySpec( pubKeySeed ) );
          // Decipher
          String roundtripMessage = decrypt_RSA( encryptedText, publicKey );
          if( DEBUG ) {
            System.out.println( "Attempting roundtrip..." );
            System.out.println( roundtripMessage );
            System.out.println();
            writeStringToFile( roundtripMessage, "plaintext_roundtrip.txt" );
          }

          // -------|---------|
          // Sign the message
          // -------|---------|
          String signature = sign( SIGNATURE, privateKey );
          if( DEBUG ) {
            System.out.println( "Signature complete: " + signature );
            System.out.println();
            System.out.println( "Attempting signature verification ('" + SIGNATURE + "')..." );
            boolean isCorrect = verify( SIGNATURE, signature, publicKey );
            System.out.println("Signature correct: " + isCorrect);
          }

          System.out.println( "ENCRYPTION COMPLETE:" );
          System.out.println( "-----BEGIN RSA MESSAGE-----" );
          System.out.println( encryptedText );
          System.out.println( "-----END RSA MESSAGE-----" );
          System.out.println();
          System.out.println( "-----BEGIN RSA SIGNATURE-----" );
          System.out.println( signature );
          System.out.println( "-----END RSA SIGNATURE-----" );
          System.out.println();

          // -------|---------|
          // Save cipher to file
          // -------|---------|
          String fileOutput = null;
          System.out.print( "Enter file output name or leave blank to write to 'ciphertext_output.txt': " );
          if( FASTMODE ) {
            fileOutput = "ciphertext_output.txt";
            System.out.println( fileOutput );
            System.out.println();
          }
          else {
            fileOutput = userInput.next();
            System.out.println();
          }
          writeStringToFile( encryptedText, fileOutput );
          System.out.println( "Ciphertext written." );
          System.out.println();

          // -------|---------|
          // Save signature to file
          // -------|---------|
          System.out.print( "Enter signature output name or leave blank to write to 'signature_output.txt': " );
          if( FASTMODE ) {
            fileOutput = "signature_output.txt";
            System.out.println( fileOutput );
            System.out.println();
          }
          else {
            fileOutput = userInput.next();
            System.out.println();
          }
          writeStringToFile( signature, fileOutput );
          System.out.println( "Signature written. End of Encryption Case" );
          System.out.println();
        } // Closing Encryption Case

        // -------|---------|---------|---------|
        // DECRYPT CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "D" ) && LOGGED_IN ) {
          System.out.println( "Decryption with PUBLIC key (e.g. - broadcast from known sender)" );




// -------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|-------|
//
// UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION !
//
// -------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|-------|

        } // Closing Decryption Case

        // -------|---------|---------|---------|
        // EXIT CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "X" ) ) {
          isRunning = false;
        }

        // -------|---------|---------|---------|
        // SAVE + EXIT CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "SX" ) ) {
          System.out.println( "Saving state and exiting..." );
          writeToFile( userDB,   USERDB_OUT      );
          writeToFile( idKEKDB,  KEY_KEKDB_OUT   );
          writeToFile( pubKeys,  PUB_KEYSDB_OUT  );
          writeToFile( privKeys, PRIV_KEYSDB_OUT );
          writeToFile( keyIDs,   USER_KEYID_OUT  );
          writeToFile( kvcDB,    KEYID_KVCDB_OUT );
          isRunning = false;
        }

        else {
          System.out.println( "Selection not recognized." );
          System.out.println();
        }
      } // Closing SERVER WHILE LOOP

      if( DEBUG ) {
        System.out.println( "Server loop complete. Exiting..." );
      }
    } // Closing SERVER ROLE

// -------|---------|---------|---------|
// CLIENT
// -------|---------|---------|---------|
    else if( role.equals( "CLIENT" ) ) {
      System.out.println( "CLIENT SUITE ACTIVATED" );
    } // Closing CLIENT ROLE
  } //  Closing Main()


//-------|---------|---------|---------|---------|---------|---------|---------|
//
// SUPPORT FUNCTIONS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|---------|---------|---------|---------|
//
// ENCRYPT / DECRYPT
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// sign()/verify()
//-------|---------|---------|---------|
  public static String sign(String plainText, PrivateKey privateKey) throws Exception {
    Signature privateSignature = Signature.getInstance("SHA256withRSA");
    privateSignature.initSign(privateKey);
    privateSignature.update(plainText.getBytes(UTF_8));

    byte[] signature = privateSignature.sign();

    return Base64.getEncoder().encodeToString(signature);
  } // Closing sign()
  public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(publicKey);
    publicSignature.update(plainText.getBytes(UTF_8));

    byte[] signatureBytes = Base64.getDecoder().decode(signature);

    return publicSignature.verify(signatureBytes);
  } // Closing verify()

//-------|---------|---------|---------|
// encrypt_RSA()
//-------|---------|---------|---------|
  public static String encrypt_RSA(String plainText, PrivateKey privateKey) throws Exception {
    Cipher encryptCipher = Cipher.getInstance("RSA");
    encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

    byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

    return Base64.getEncoder().encodeToString(cipherText);
  } // Closing encrypt_RSA()

//-------|---------|---------|---------|
// decrypt_RSA()
//-------|---------|---------|---------|
  public static String decrypt_RSA(String cipherText, PublicKey publicKey) throws Exception {
    byte[] bytes = Base64.getDecoder().decode(cipherText);

    Cipher decriptCipher = Cipher.getInstance("RSA");
    decriptCipher.init(Cipher.DECRYPT_MODE, publicKey);

    return new String(decriptCipher.doFinal(bytes), UTF_8);
  } // Closing decrypt_RSA()

//-------|---------|---------|---------|
// confirmKVC()
//-------|---------|---------|---------|
  public static boolean confirmKVC( String kvcToConfirm, String tgtval, String kek ) {
    boolean retbool = true;
    String decryption = decrypt_AES( kvcToConfirm, kek );
    if( DEBUG ) {
      System.out.println( "KVC Confirmation result: " + decryption );
    }
    retbool = decryption.equals( tgtval );
    return retbool;
  } // Closing confirmKVC()


//-------|---------|---------|---------|
// encrypt_AES()
//-------|---------|---------|---------|
  public static String encrypt_AES( String plaintext, String secret ) {
    try {
      setKey( secret );
      Cipher cipher = Cipher.getInstance( "AES/ECB/PKCS5Padding" );
      cipher.init( Cipher.ENCRYPT_MODE, secretKey );
      return Base64.getEncoder( ).encodeToString( cipher.doFinal( plaintext.getBytes( "UTF-8" ) ) );
    } 
    catch( Exception e ) {
      System.out.println( "Encryption error: " + e.toString( ) );
    }
    return null;
  } // Closing encrypt_AES()

//-------|---------|---------|---------|
// decrypt_AES()
//-------|---------|---------|---------|
  public static String decrypt_AES( String ciphertext, String secret ) {
    try {
      setKey( secret );
      Cipher cipher = Cipher.getInstance( "AES/ECB/PKCS5PADDING" );
      cipher.init( Cipher.DECRYPT_MODE, secretKey );
      String retString = new String( cipher.doFinal( Base64.getDecoder( ).decode( ciphertext ) ) );
      return retString;
    } 
    catch( Exception e ) {
      System.out.println( "Decryption error: " + e.toString( ) );
    }
    return null;
  } // Closing decrypt_AES()

//-------|---------|---------|---------|
// xorHex()
//-------|---------|---------|---------|
  public static String xorHex( String a, String b ) {
    // TODO: Validation
    char[] chars = new char[a.length()];
    for (int i = 0; i < chars.length; i++) {
      chars[i] = toHex(fromHex(a.charAt(i)) ^ fromHex(b.charAt(i)));
    }
    return new String(chars);
  }

//-------|---------|---------|---------|
// hash_SHA256
//-------|---------|---------|---------|
  public static String hash_SHA256( String input ) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest( input.getBytes(StandardCharsets.UTF_8));

    String retString = bytesToHex( hash );
    return retString;
  }

//-------|---------|---------|---------|---------|---------|---------|---------|
//
// KEY MANAGEMENT
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// generateKeyPair()
//-------|---------|---------|---------|
  public static KeyPair generateKeyPair( String tweak ) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize( 2048, new SecureRandom( tweak.getBytes( ) ) );
    KeyPair pair = generator.generateKeyPair( );
    return pair;
  } // Closing generateKeyPair()

  private static SecretKeySpec secretKey; // Used by AES encrypt/decrypt
  private static byte[] key;

//-------|---------|---------|---------|
// setKey()
//-------|---------|---------|---------|
  public static void setKey( String myKey ) {
    MessageDigest sha = null;
    try {
      key = myKey.getBytes( "UTF-8" );
      sha = MessageDigest.getInstance( "SHA-1" );
      key = sha.digest( key );
      key = Arrays.copyOf( key, 16 ); 
      secretKey = new SecretKeySpec( key, "AES" );
    } 
    catch( NoSuchAlgorithmException e ) {
      e.printStackTrace( );
    } 
    catch( UnsupportedEncodingException e ) {
      e.printStackTrace( );
    }
  } // Closing setKey()

//-------|---------|---------|---------|
// calcKeyID()
//-------|---------|---------|---------|
  public static String calcKeyID( String username, String keypass ) {
    String passhash = null;
    try {
      passhash = hash_SHA256( keypass );
    }
    catch (Exception e) {
      e.printStackTrace(System.out);
    }
    String keyID = WHO_AM_I + " " + passhash;
    return keyID;    
  } // Closing calcKeyID()

  
//-------|---------|---------|---------|---------|---------|---------|---------|
//
// DATABASE OPERATIONS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// addPair
//-------|---------|---------|---------|
// Attempts to add a key:value pair to a HashSet, but only if the Key is not already present
// Aborts if key is found
  public static boolean addPair( HashSet<String[]> database, String[] pair ) {
    String key = pair[0];
    String value = pair[1];
    if( !doesContainKeyValPair( database, key, value ) ) {
      if( DEBUG ) {
        System.out.println( "Key (" + key + ") : Value (" + value + ") not found. Adding... " );
      }
      database.add( pair );
      return true;
    }
    if( DEBUG ) {
      System.out.println( "Key (" + key + ") : Value (" + value + ") found. Aborting... " );
    }
    return false;
  } // Closing addPair()

//-------|---------|---------|---------|
// doesContainKeyValPair
//-------|---------|---------|---------|  
// Searches through a database looking for a given key
  public static boolean doesContainKeyValPair( HashSet<String[]> database, String key, String value ) {
    boolean doesContain = false;
    Iterator<String[]> i = database.iterator();
    while( i.hasNext( ) ) {
      String[] currEntry = i.next();
      if( currEntry[0].equals( key )) {
        if( DEBUG ) {
          System.out.println( "Key match found!" );
        }
        if( currEntry[1].equals( value ) ) {
          if( DEBUG ) {
            System.out.println( "Value match found!" );
          }
          doesContain = true;
          return doesContain;
        }
      } // Closing key match case
    }
    if( DEBUG ) {
      System.out.println( "No key:value match found." );
    }
    return doesContain;
  } // Closing doesContainKeyValPair()

//-------|---------|---------|---------|
// doesContainKey
//-------|---------|---------|---------|  
// Searches through a database looking for a given key
  public static boolean doesContainKey( HashSet<String[]> database, String key ) {
    boolean doesContain = false;
    Iterator<String[]> i = database.iterator();
    while( i.hasNext( ) ) {
      String[] currEntry = i.next();
      if( currEntry[0].equals( key )) {
        if( DEBUG ) {
          System.out.println( "Key match found!" );
        }
        return true;
      }
    }
    System.out.println( "No key match found." );
    return false;
  } // Closing doesContainKey()

//-------|---------|---------|---------|---------|---------|---------|---------|
//
// GETTERS/SETTERS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// countByKey()
//-------|---------|---------|---------|
  public static int countByKey( HashSet<String[]> database, String tgtkey ) {
    int count = 0;
    Iterator<String[]> i = database.iterator();
    // For every key in the database...
    while( i.hasNext( ) ) {
      String[] currEntry = i.next();
      // If the DB key matches the target key
      if( currEntry[0].equals( tgtkey ) ) {
        count++;
      }
    }
    return count;
  }

//-------|---------|---------|---------|
// getValue()
//-------|---------|---------|---------|
  public static String getValue( HashSet<String[]> database, String key ) {
    String retVal = "NOT_FOUND";
    // Make an iterator and scan over the database contents
    Iterator<String[]> i = database.iterator();
    while( i.hasNext( ) ) {
      String[] currEntry = i.next();
      if( currEntry[0].equals( key ) ) {
        retVal = currEntry[1];
        if( DEBUG ) {
          System.out.println( "Key found. Returning '" + retVal + "'..." );
        }
        return retVal;
      }
    }
    if( DEBUG ) {
      System.out.println( "Key not found. Returning 'NOT_FOUND'." );
    }
    return retVal;
  } // Closing getValue()

//-------|---------|---------|---------|---------|---------|---------|---------|
//
// LOADERS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// readFile
//-------|---------|---------|---------|  
// Reads a file and returns the contents as a String
  public static String readFile( String filename ) {    
    File f = new File( filename );
    Scanner fileReader = null;
    try {
      fileReader = new Scanner( f );
    }
    catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    String retString = "";
    while( fileReader.hasNextLine() ) {
      retString += fileReader.nextLine();
    }
    if( DEBUG ) {
      System.out.println( "Read File: " + filename );
      System.out.println( "Contents : " );
      System.out.println( retString );
      System.out.println();
    }
    return retString;
  } // Closing readFile()

//-------|---------|---------|---------|
// writeStringToFile
//-------|---------|---------|---------|  
// Takes a HashSet<String[Key:Value]> and writes to file in no particular order
  public static boolean writeStringToFile( String text, String filename ) {    
    FileWriter fw = null;
    BufferedWriter writer = null;
    try {
      fw = new FileWriter( filename );
      writer = new BufferedWriter( fw );
      writer.write( text );
      writer.close();
      return true;
    }
    catch (IOException e) {
      e.printStackTrace();
      return false;
    }
  } // Closing writeStringToFile()
//-------|---------|---------|---------|
// writeToFile
//-------|---------|---------|---------|  
// Takes a HashSet<String[Key:Value]> and writes to file in no particular order
  public static boolean writeToFile( HashSet<String[]> database, String filename ) {    
    FileWriter fw = null;
    BufferedWriter writer = null;
    try {
      fw = new FileWriter( filename );
      writer = new BufferedWriter( fw );
      Iterator<String[]> i = database.iterator();
      while( i.hasNext( ) ) {
        String[] currEntry = i.next();
        String line = ( currEntry[0] + " " + currEntry[1] + "\n" );
        writer.write( line );
      }
      writer.close();
      return true;
    }
    catch (IOException e) {
      e.printStackTrace();
      return false;
    }
  } // Closing writeToFile()

//-------|---------|---------|---------|
// loadSecret()
//-------|---------|---------|---------|
// Loads HSM secret from file
  public static String loadSecret( String filename ) {
    boolean LOCAL_DEBUG = false;
//-------|---------|
// STEP 1 - SET FILENAME
//-------|---------|
    // Ignore: filename is passed in as formal parameter    
    // Check result
    if( DEBUG ) {
      System.out.println( "Filename: '" + filename + "'" );
    }
//-------|---------|
// STEP 2 - OPEN TARGET FILE
//-------|---------|
    // Do work for this code section
    File f = new File( filename );
    if( DEBUG && LOCAL_DEBUG) {
      System.out.println( "Checking file open operation:" );
      System.out.println( "  File name    : " + f.getName()         );
      System.out.println( "  Path         : " + f.getPath()         );
      System.out.println( "  Absolute path: " + f.getAbsolutePath() );
      System.out.println( "  Parent       : " + f.getParent()       );
      System.out.println( "  Exists       : " + f.exists()          );
      if( f.exists() ) {
        System.out.println();
        System.out.println( "File exists. Checking file states:" );
        System.out.println( "  Is writeable      : " + f.canWrite()    ); 
        System.out.println( "  Is readable       : " + f.canRead()     ); 
        System.out.println( "  Is a directory    : " + f.isDirectory() ); 
        System.out.println( "  File Size in bytes: " + f.length()      );
        System.out.println();
        System.out.println( "Printing file object:" );
        System.out.println( f );
      }
    }
//-------|---------|
// STEP 3 - LOAD FILE OBJECT TO A SCANNER
//-------|---------|
    Scanner fileReader = null;
    try {
      fileReader = new Scanner( f );
      if( DEBUG && LOCAL_DEBUG) {
        System.out.print( fileReader );
      }
    }
    catch (FileNotFoundException e) {
      e.printStackTrace();
    }
//-------|---------|
// STEP 4 - Make a return String
//-------|---------|
    String retString = fileReader.nextLine();
    return retString;
  } // Closing loadSecret()

//-------|---------|---------|---------|
// loadFromFile()
//-------|---------|---------|---------|
// Loads a correctly formatted (space delimited) key:value pair HashSet from file and returns it
  public static HashSet<String[]> loadFromFile( String filename ) {
    boolean LOCAL_DEBUG = false;
//-------|---------|
// STEP 1 - SET FILENAME
//-------|---------|
    // Ignore: filename is passed in as formal parameter    
    // Check result
    if( DEBUG ) {
      System.out.println( "Load from file: '" + filename + "'" );
    }
//-------|---------|
// STEP 2 - OPEN TARGET FILE
//-------|---------|
    // Do work for this code section
    File f = new File( filename );
    if( DEBUG && LOCAL_DEBUG) {
      System.out.println( "Checking file open operation:" );
      System.out.println( "  File name    : " + f.getName()         );
      System.out.println( "  Path         : " + f.getPath()         );
      System.out.println( "  Absolute path: " + f.getAbsolutePath() );
      System.out.println( "  Parent       : " + f.getParent()       );
      System.out.println( "  Exists       : " + f.exists()          );
      if( f.exists() ) {
        System.out.println();
        System.out.println( "File exists. Checking file states:" );
        System.out.println( "  Is writeable      : " + f.canWrite()    ); 
        System.out.println( "  Is readable       : " + f.canRead()     ); 
        System.out.println( "  Is a directory    : " + f.isDirectory() ); 
        System.out.println( "  File Size in bytes: " + f.length()      );
        System.out.println();
        System.out.println( "Printing file object:" );
        System.out.println( f );
      }
    }
//-------|---------|
// STEP 3 - LOAD FILE OBJECT TO A SCANNER
//-------|---------|
    Scanner fileReader = null;
    try {
      fileReader = new Scanner( f );
      if( DEBUG && LOCAL_DEBUG) {
        System.out.print( fileReader );
      }
    }
    catch (FileNotFoundException e) {
      e.printStackTrace();
    }
//-------|---------|
// STEP 4 - Make a return hashset
//-------|---------|
    HashSet<String[]> retHashset = new HashSet<String[]>();
//-------|---------|
// STEP 5 - Read over the file and jam everything into the set
//-------|---------|
    while( fileReader.hasNext() ) {
      String currLine = fileReader.nextLine();
      Scanner lineReader = new Scanner( currLine );
      String[] currPair = new String[2];
      currPair[0] = lineReader.next();
      currPair[1] = lineReader.next();
      retHashset.add( currPair );
    }
    return retHashset;
  } // Closing loadFromFile()

//-------|---------|---------|---------|---------|---------|---------|---------|
//
// RENDERERS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// renderHashSet()
//-------|---------|---------|---------|
// Writes a [Key:Value] HashSet to console in no particular order
  public static void renderHashSet( HashSet<String[]> h ) {
    Iterator<String[]> i = h.iterator();
    while( i.hasNext( ) ) {
      String[] currEntry = i.next();
      System.out.println( currEntry[0] + " : " + currEntry[1] ); 
    }
  } // Closing renderHashSet()

//-------|---------|---------|---------|
// renderOptions()
//-------|---------|---------|---------|
  public static void renderOptions() {
    System.out.println( "OPTIONS -|---------|---------|---------|---------|---------|---------|---------|" );
    System.out.println( "  N - make a New user account" );
    System.out.println( "  L - Login" );
    System.out.println( "  R - Report the contents of the vHSM" );
    if( LOGGED_IN ) {
      System.out.println( "  C - Create Key" );
      System.out.println( "  E - Encrypt" );
      System.out.println( "  S - Sign" );
    }
    else if( !LOGGED_IN ) {
      System.out.println( "  C - (Unavailable - Please log in) Create Key" );
      System.out.println( "  E - (Unavailable - Please log in) Encrypt" );
      System.out.println( "  S - (Unavailable - Please log in) Sign" );
    }
    System.out.println( "  X - eXit" );
    System.out.println( "  SX - Save + eXit" );
    System.out.print( "Please select an option: " );
  } // Closing renderOptions()

//-------|---------|---------|---------|---------|---------|---------|---------|
//
// FORMAT CONVERSION
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// bytesToHex
//-------|---------|---------|---------|
private static String bytesToHex(byte[] hash) {
    StringBuffer hexString = new StringBuffer();
    for (int i = 0; i < hash.length; i++) {
    String hex = Integer.toHexString(0xff & hash[i]);
    if(hex.length() == 1) hexString.append('0');
        hexString.append(hex);
    }
    return hexString.toString();
} // Closing bytesToHex()

//-------|---------|---------|---------|
// fromHex()
//-------|---------|---------|---------|
  public static int fromHex(char c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    throw new IllegalArgumentException();
  }

//-------|---------|---------|---------|
// toHex( )
//-------|---------|---------|---------|
  public static char toHex(int nybble) {
    if (nybble < 0 || nybble > 15) {
      throw new IllegalArgumentException();
    }
    char retChar = "0123456789abcdef".charAt(nybble);
    return retChar;
  } // Closing toHex( )


} // Closing class Main
