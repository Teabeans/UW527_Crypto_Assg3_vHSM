//-------|---------|---------|---------|---------|---------|---------|---------|
//
// UW CSS 527 - Assg3 - Virtual Hardware Security Module (HSM)
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
// Modified: 2020.02.26
// For the University of Washington Bothell, CSS 527
// Winter 2020, Masters in Cybersecurity Engineering (MCSE)
//

//-----------------------------------------------------------------------------|
// File Description
//-----------------------------------------------------------------------------|
//
// Driver for virtual hardware security module

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

  static boolean DEBUG      = true;
  static boolean FASTMODE   = false;
  static boolean LOGGED_IN  = false;
  static boolean PERSISTENT = true;
  static String WHO_AM_I   = null;
  static String MY_SECRET  = null;
  static final String KEY_COUNT       = "keycount.txt";
  static final String KVC_PASSPHRASE  = "test"; // Per assignment specification
  static final String SIGNATURE       = "MyNameIsInigoMontoyaYouKilledMyFatherPrepareToDie";
  static final String HSM_SECRET      = "hsmsecret.txt";
  static final String USERDB_IN       = "user_passwordhash.txt";
  static       String USERDB_OUT      = "user_passwordhash_output.txt";
  static final String KEY_KEKDB_IN    = "keyid_KEK.txt";
  static       String KEY_KEKDB_OUT   = "keyid_KEK_output.txt";
  static final String PUB_KEYSDB_IN   = "publickey_keyID.txt";
  static       String PUB_KEYSDB_OUT  = "publickey_keyID_output.txt";
  static final String PRIV_KEYSDB_IN  = "privatekey_keyID.txt";
  static       String PRIV_KEYSDB_OUT = "privatekey_keyID_output.txt";
  static final String USER_KEYID_IN   = "user_KeyIDs.txt";
  static       String USER_KEYID_OUT  = "user_KeyIDs_output.txt";
  static final String KEYID_KVCDB_IN  = "keyid_KVC.txt";
  static       String KEYID_KVCDB_OUT = "keyid_KVC_output.txt";

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

    if( PERSISTENT ) {
      USERDB_OUT      = USERDB_IN      ;
      KEY_KEKDB_OUT   = KEY_KEKDB_IN   ;
      PUB_KEYSDB_OUT  = PUB_KEYSDB_IN  ;
      PRIV_KEYSDB_OUT = PRIV_KEYSDB_IN ;
      USER_KEYID_OUT  = USER_KEYID_IN  ;
      KEYID_KVCDB_OUT = KEYID_KVCDB_IN ;
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
      // Load known information from the databases
      HashSet<String[]> userDB   = loadFromFile( USERDB_IN      );
      HashSet<String[]> idKEKDB  = loadFromFile( KEY_KEKDB_IN   );
      HashSet<String[]> pubKeys  = loadFromFile( PUB_KEYSDB_IN  );
      HashSet<String[]> privKeys = loadFromFile( PRIV_KEYSDB_IN );
      HashSet<String[]> keyIDs   = loadFromFile( USER_KEYID_IN  );
      HashSet<String[]> kvcDB    = loadFromFile( KEYID_KVCDB_IN );
      MY_SECRET = loadSecret( HSM_SECRET );
      int CURR_KEYCOUNT = loadIntFromFile( KEY_COUNT );

      // Auto-login
      if( FASTMODE ) {
        LOGGED_IN = true;
        WHO_AM_I = "teabeans";
      }

      System.out.println();
      System.out.println( "\u001b[37;1mWELCOME TO THE VIRTUAL HSM: \u001b[0m" );

      Scanner userInput = new Scanner(System.in);
      boolean isRunning = true;
      while( isRunning ) {
        renderOptions();
        String choice = userInput.next();
        System.out.println();

        // -------|---------|---------|---------|
        // NEW USER ACCOUNT CASE
        // -------|---------|---------|---------|
        if( choice.equals( "N" ) ) {
          System.out.println( "---NEW USER SELECTED---" );
          System.out.print( "\u001b[37;1mEnter new username: \u001b[0m" );
          String username = userInput.next();
          // Check if user is already in the database
          if( doesContainKey( userDB, username ) ) {
            System.out.println( "\u001b[31;1mUsername unavailable\u001b[0m. Aborting..." );
            System.out.println();
            continue;
          }
          System.out.println( "Username available!" );
          System.out.print( "\u001b[37;1mSelect password   : \u001b[0m");
          String password = new String( System.console( ).readPassword( ) );
          String hash = null;
          try {
            hash = hash_SHA256( password );
          }
          catch (Exception e) {
            e.printStackTrace(System.out);
          }
          if( DEBUG ) {
            System.out.println( "Password: " + password + " => [SHA-256] => " + hash );
          }
          System.out.println( "Password accepted! Hashing and saving..." );
          String[] pair = new String[2];
          pair[0] = username;
          pair[1] = hash;
          boolean addResult = addPair( userDB, pair );
          if( DEBUG ) {
            System.out.println( "Add result: " + addResult );
            renderHashSet( userDB );
          }
          System.out.println( "\u001b[32;1mAccount '" + username + "' created!\u001b[0m" );
          System.out.println();
        } // Closing new user account case

        // -------|---------|---------|---------|
        // LOGIN CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "L" ) ) {
          System.out.println( "---LOGIN SELECTED---" );
          System.out.print( "Enter username: " );
          String username = userInput.next();
          System.out.print( "Enter password: " );
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
            System.out.println( "Password: " + password + " => [SHA-256] => " + hash );
          }
          // -------|---------|
          // Check credentials against database
          // -------|---------|
          if( getValue( userDB, username ).equals( hash ) ) {
            System.out.println( "Username:Password accepted. \u001b[32;1mLogin successful\u001b[0m." );
            System.out.println();
            LOGGED_IN = true;
            WHO_AM_I = username;
          }
          else {
            System.out.println( "Username:Password not found. \u001b[31;1mLogin denied\u001b[0m. Logging out..." );
            System.out.println();
            LOGGED_IN = false;
            WHO_AM_I = null;
          }

        } // Closing login case

        // -------|---------|---------|---------|
        // REPORT CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "R" ) ) {
          System.out.println( "---REPORT SELECTED---");
          System.out.println( "Reporting internal state of vHSM..." );
          System.out.println( "Logged in   : " + LOGGED_IN     );
          System.out.println( "Current User: " + WHO_AM_I      );
          System.out.println( "vHSM Secret : " + MY_SECRET     );
          System.out.println( "Current Key : " + CURR_KEYCOUNT );

          System.out.println();

          System.out.println( "\u001b[33;1mUSER       : PASSWORD HASH \u001b[0m" );
          renderHashSetShort( userDB, 61 );
          System.out.println();

          System.out.println( "\u001b[33;1mOWNER      : KEY ID \u001b[0m" );
          renderHashSetShort( keyIDs, 62 );
          System.out.println();

          System.out.println( "\u001b[33;1mKEY ID     : KEY ENCRYPTION KEY (KEK) \u001b[0m" );
          renderHashSetShort( idKEKDB, 62 );
          System.out.println();

          System.out.println( "\u001b[33;1mKEY ID     : KEY VERIFICATION CODE (KVC) \u001b[0m" );
          renderHashSetShort( kvcDB, 62 );
          System.out.println();

          System.out.println( "\u001b[33;1mKEY ID     : PUBLIC KEY \u001b[0m" );
          renderHashSetShort( pubKeys, 62 );
          System.out.println();

          System.out.println( "\u001b[33;1mKEY ID     : ENCRYPTED PRIVATE KEY \u001b[0m" );
          renderHashSetShort( privKeys, 62 );
          System.out.println();
        } // Closing HSM Report case

        // -------|---------|---------|---------|
        // CREATE KEY CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "C" ) && LOGGED_IN ) {
          System.out.println( "---CREATE KEY SELECTED---" );

          if( DEBUG ) {
            System.out.println( "|---------|---------|---------|---------|" );
            System.out.println( "| Generate KeyID" );
            System.out.println( "|---------|---------|---------|---------|" );
          }
          // In form: 'USERNAME:KEYNUMBER'
          String keyID = calcKeyID( WHO_AM_I, CURR_KEYCOUNT );

          if( DEBUG ) {
            System.out.println( "KeyID ('" + keyID + "') created." );
            System.out.println();
          }

          if( DEBUG ) {
            System.out.println( "|---------|---------|---------|---------|" );
            System.out.println( "| Add KeyID to database" );
            System.out.println( "|---------|---------|---------|---------|" );
          }

          String[] userKeyPair = new String[2];
          userKeyPair[0] = WHO_AM_I;
          userKeyPair[1] = keyID;
          addPair( keyIDs, userKeyPair );

          if( DEBUG ) {
            System.out.println( "KeyID ('" + keyID + "') added to database." );
            System.out.println();
          }

          if( DEBUG ) {
            System.out.println( "|---------|---------|---------|---------|" );
            System.out.println( "| Acquire Key Password" );
            System.out.println( "|---------|---------|---------|---------|" );
          }
          System.out.print( "\u001b[37;1mEnter Key Password: \u001b[0m" );
          String keypass = null;
          if( FASTMODE ) {
            keypass = "foobarbaz";
          }
          else {
            keypass = new String( System.console( ).readPassword( ) );
          }

          if( DEBUG ) {
            System.out.println( "Key Password input acquired:" );
            System.out.println( "  USER   : " + WHO_AM_I );
            System.out.println( "  KEY ID#: " + (CURR_KEYCOUNT) );
            System.out.println( "  PASS   : " + keypass );
            System.out.println();
          }

          CURR_KEYCOUNT++;

          if( DEBUG ) {
            System.out.println( "|---------|---------|---------|---------|" );
            System.out.println( "| RSA generate Public and Private keys" );
            System.out.println( "|---------|---------|---------|---------|" );
          }

          KeyPair kp = generateKeyPair( keypass );

          // KeyPair kp = null;
          Key pub = kp.getPublic( );
          Key pvt = kp.getPrivate( );

          // Convert to Base64 representation
          Base64.Encoder encoder = Base64.getEncoder( );
          String pubKey_64 = encoder.encodeToString( pub.getEncoded( ) );
          String pvtKey_64 = encoder.encodeToString( pvt.getEncoded( ) );

          if( DEBUG ) {
            System.out.println( "KEY.PUBLIC result:" );
            System.out.println( "  Format: " + pub.getFormat( ) );
            System.out.println( "  Value : " + pub.getEncoded( ) );
            System.out.println( String.format("  Base64: %1$.66s[...]", pubKey_64 ) );
            System.out.println();
            
            System.out.println( "KEY.PRIVATE result:" );
            System.out.println( "  Format: " + pvt.getFormat( ) );
            System.out.println( "  Value : " + pvt.getEncoded( ) );
            System.out.println( String.format("  Base64: %1$.66s[...]", pvtKey_64 ) );
            System.out.println();
          }

          if( DEBUG ) {
            System.out.println( "|---------|---------|---------|---------|" );
            System.out.println( "| Calculate Key Encryption Key (KEK)" );
            System.out.println( "|---------|---------|---------|---------|" );
          }
          // KEK == (HSMSecretKey) XOR (SHA256(KeyPassword))
          String sha256KeyPass = null;
          try {
            sha256KeyPass = hash_SHA256( keypass );
          }
          catch( Exception e ) {
            e.printStackTrace( System.out );
          }

          if( DEBUG ) {
            System.out.print( String.format( "'%-13s'" , keypass ) );
            System.out.print( " ===[SHA-256]==> " );
            System.out.println( String.format( "%1$.44s[...]" , sha256KeyPass ) );
            System.out.println();
            System.out.println( "Attempting XOR of: " );
            System.out.println( "  HSM Secret     : " + MY_SECRET );
            System.out.println( "  Password Hash  : " + sha256KeyPass );
            System.out.println();
          }

          String keyEncryptionKey = xorHex( sha256KeyPass, MY_SECRET );

          if( DEBUG ) {
            System.out.println( "XOR Result (KEK): " );
            System.out.println( "  Key-Encrypt-Key: " + keyEncryptionKey );
            System.out.println();
          }

          if( DEBUG ) {
            System.out.println( "|---------|---------|---------|---------|" );
            System.out.println( "| Store KEK to server" );
            System.out.println( "|---------|---------|---------|---------|" );
          }

          String[] idAndKEK = new String[2];
          idAndKEK[0] = keyID; // Key ID
          idAndKEK[1] = keyEncryptionKey;
          addPair( idKEKDB, idAndKEK );

          if( DEBUG ) {
            System.out.println( "KeyID : KEK stored to database." );
            System.out.println();
          }

          // -------|---------|
          // Store unencrypted pubKey to server
          // -------|---------|
          String[] idAndPubkey = new String[2];
          idAndPubkey[0] = keyID;
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
          idAndKVC[0] = keyID;
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
          idAndPrivkey[0] = keyID;
          idAndPrivkey[1] = pvtKey_encrypted;
          addPair( privKeys, idAndPrivkey);
          
          System.out.println( "RSA keypair generated from password." );
          System.out.println();
        } // Closing Key Creation case

        // -------|---------|---------|---------|
        // ENCRYPT CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "E" ) && LOGGED_IN ) {
          System.out.println( "Encryption with PRIVATE key selected (authenticity, no confidentiality)" );

          // -------|---------|
          // Check if User has Keys
          // -------|---------|
          //                         HashSet Key (not value)
          int keyCount = countByKey( keyIDs, WHO_AM_I );
          if( keyCount == 0 ) {
            System.out.println( "No keys registered to you. Please create a key before encrypting." );
            System.out.println();
            continue;
          }
          if( DEBUG ) {
            System.out.println( "(" + keyCount + ") keys found! Continuing..." );
          }
          // -------|---------|
          // Prompt user for key ID
          // -------|---------|
          if( DEBUG ) {
            renderHashSetShort( keyIDs, 20 );
          }
          System.out.print( "Enter desired key identity number: " );
          int keyidNumber = userInput.nextInt();

          if( DEBUG ) {
            System.out.println( "Performing key ID number and username concatenation, key lookup." );
          }

          String keyIdentifier = WHO_AM_I + ":" + keyidNumber;
          boolean idLookupResult = doesContainKeyValPair( keyIDs, WHO_AM_I, keyIdentifier );

          if( DEBUG ) {
            System.out.println( "Key ID number lookup result. Does exist: " + idLookupResult );
          }

          if( idLookupResult == false ) {
            System.out.println( "Key ownership cannot be verified by ID. Aborting..." );
            continue;
          }
          System.out.println( "Key ownership verified by ID!" );

          // -------|---------|
          // Prompt user for key selection
          // -------|---------|
          System.out.print( "Enter key password for this ID (" + keyidNumber + "): " );
          String identifier = null;
          if( FASTMODE ) {
            identifier = "foobarbaz";
          }
          else {
            identifier = new String( System.console( ).readPassword( ) );
          }
          
          // -------|---------|
          // Acquire Plaintext
          // -------|---------|
          System.out.println( "Reading plaintext from file: 'plaintext.txt'... " );
          String plaintext = readFile( "plaintext.txt" );

          if( DEBUG ) {
            System.out.println( "Plaintext received: " );
            System.out.println( plaintext );
          }

          // -------|---------|
          // Acquire Key using lookup
          // -------|---------|
          String kekFromDB = getValue( idKEKDB, keyIdentifier );

          // -------|---------|
          // Calculate Key Encryption Key (KEK)
          // -------|---------|
          // KEK == (HSMSecretKey) XOR (SHA256(KeyPassword))
          String sha256KeyPass = null;
          try {
            sha256KeyPass = hash_SHA256( identifier );
          }
          catch( Exception e ) {
            e.printStackTrace( System.out );
          }
          String keyEncryptionKey = xorHex( sha256KeyPass, MY_SECRET );
          boolean kekCompare = kekFromDB.equals( keyEncryptionKey );
          if( DEBUG ) {
            System.out.println( "KEK calculated! Comparing... " );
            System.out.println( "KEK from DB == KEK calculated here: " + kekCompare );
          }


          String kvcFromDB = getValue( kvcDB,    keyIdentifier );
          String keyFromDB = getValue( privKeys, keyIdentifier );

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
          keyFromDB = getValue( pubKeys, keyIdentifier );
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
          System.out.print( "Enter ciphertext output filename: " );
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
          System.out.print( "Enter signature output filename: " );
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
          System.out.println( "No decryption case per assignment specification." );
        } // Closing Decryption Case

// -------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|-------|
//
// UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION ! UNDER CONSTRUCTION !
//
// -------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|-------|
        // -------|---------|---------|---------|
        // TARE CASE
        // -------|---------|---------|---------|
        else if( choice.equals( "T" ) ) {
          System.out.println( "Taring. Dumping databases..." );
          System.out.println();
          CURR_KEYCOUNT = 0;
          obliviate( userDB );
          obliviate( idKEKDB );
          obliviate( pubKeys );
          obliviate( privKeys );
          obliviate( keyIDs );
          obliviate( kvcDB );
        }

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
          writeIntToFile( CURR_KEYCOUNT, KEY_COUNT );
          writeToFile( userDB,   USERDB_OUT      );
          writeToFile( idKEKDB,  KEY_KEKDB_OUT   );
          writeToFile( pubKeys,  PUB_KEYSDB_OUT  );
          writeToFile( privKeys, PRIV_KEYSDB_OUT );
          writeToFile( keyIDs,   USER_KEYID_OUT  );
          writeToFile( kvcDB,    KEYID_KVCDB_OUT );
          isRunning = false;
        }

        else {
          System.out.println( "Selection not recognized or invalid (are you logged in?)." );
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
  public static String calcKeyID( String username, int idNumber ) {
    String keyID = username + ":" + idNumber;
    return keyID;
  } // Closing calcKeyID()

  
//-------|---------|---------|---------|---------|---------|---------|---------|
//
// DATABASE OPERATIONS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// obliviate()
//-------|---------|---------|---------|
  public static void obliviate( HashSet<String[]> database ) {
    database.clear();
  } // Closing obliviate()

//-------|---------|---------|---------|
// addPair()
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
    if( DEBUG ) {
      System.out.println( "No key match found." );
    }
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
          System.out.println( "Key found! Returning Value: '" + retVal + "'..." );
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
// READERS/LOADERS
//
//-------|---------|---------|---------|---------|---------|---------|---------|

//-------|---------|---------|---------|
// loadIntFromFile()
//-------|---------|---------|---------|
  public static int loadIntFromFile( String filename ) {
    int retInt = 0;
    File f = new File( filename );
    Scanner fileReader = null;
    try {
      fileReader = new Scanner( f );
    }
    catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    retInt = fileReader.nextInt();
    return retInt;
  } // Closing loadIntFromFile()

//-------|---------|---------|---------|
// writeIntToFile()
//-------|---------|---------|---------|  
// Takes a int and writes to file
  public static boolean writeIntToFile( int number, String filename ) {    
    FileWriter fw = null;
    BufferedWriter writer = null;
    try {
      fw = new FileWriter( filename );
      writer = new BufferedWriter( fw );
      writer.write( ("" + number) );
      writer.close();
      return true;
    }
    catch (IOException e) {
      e.printStackTrace();
      return false;
    }
  } // Closing writeIntToFile()

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
// renderHashSetShort()
//-------|---------|---------|---------|
// Writes a [Key:Value] HashSet to console in no particular order
  public static void renderHashSetShort( HashSet<String[]> h, int length ) {
    Iterator<String[]> iter = h.iterator();
    while( iter.hasNext( ) ) {
      String[] currEntry = iter.next();
      if( currEntry[0].length() >= length ) {
        for( int i = 0 ; i < length ; i++ ) {
          System.out.print( currEntry[0].charAt( i ) );
        }
        System.out.print( "[...]" );
      }
      else {
        System.out.print( String.format( "%-10s" , currEntry[0] ) );
      }
      System.out.print( " : " );
      if( currEntry[1].length() >= length ) {
        for( int i = 0 ; i < length ; i++ ) {
          System.out.print( currEntry[1].charAt( i ) );
        }
        System.out.print( "[...]" );
      }
      else {
        System.out.print( currEntry[1] );
      }
      System.out.println();
    }
  } // Closing renderHashSet()

//-------|---------|---------|---------|
// renderOptions()
//-------|---------|---------|---------|
  public static void renderOptions() {
    System.out.println( "|----- OPTIONS -----|---------|---------|---------|---------|---------|---------|" );
    System.out.println( "    \u001b[1mN\u001b[0m  - make a \u001b[4mN\u001b[0mew user account" );
    System.out.println( "    \u001b[1mL\u001b[0m  - \u001b[4mL\u001b[0mogin" );
    System.out.println( "    \u001b[1mR\u001b[0m  - \u001b[4mR\u001b[0meport the contents of the vHSM" );
    if( LOGGED_IN ) {
      System.out.println( "    \u001b[1mC\u001b[0m  - \u001b[4mC\u001b[0mreate Key" );
      System.out.println( "    \u001b[1mE\u001b[0m  - \u001b[4mE\u001b[0mncrypt (w/private key)" );
      System.out.println( "    \u001b[1mD\u001b[0m  - \u001b[4mD\u001b[0mecrypt (w/public  key)" );
    }
    else if( !LOGGED_IN ) {
      System.out.println( "    \u001b[30;1mC  - (Unavailable - Please log in) Create Key \u001b[0m" );
      System.out.println( "    \u001b[30;1mE  - (Unavailable - Please log in) Encrypt (w/private key) \u001b[0m" );
      System.out.println( "    \u001b[30;1mD  - (Unavailable - Please log in) Decrypt (w/public  key) \u001b[0m" );
    }
    System.out.println( "    \u001b[1mT\u001b[0m  - \u001b[4mT\u001b[0mare HSM (drop tables)" );
    System.out.println( "    \u001b[1mX\u001b[0m  - e\u001b[4mX\u001b[0mit" );
    System.out.println( "    \u001b[1mSX\u001b[0m - \u001b[4mS\u001b[0mave + e\u001b[4mX\u001b[0mit" );
    System.out.println( "|---------|---------|---------|---------|---------|---------|---------|---------|" );
    System.out.println();
    System.out.print( "\u001b[37;1mPlease select an option: \u001b[0m" );
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
