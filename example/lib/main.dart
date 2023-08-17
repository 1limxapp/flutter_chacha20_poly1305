import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_chacha20_poly1305/flutter_chacha20_poly1305.dart';
import 'package:flutter_key_generator/flutter_key_generator.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  void encryptAndDecrypt() async {
    try {
      final key =
        await FlutterKeyGenerator.generateSymmetricKey(256);

      print("256 bit key: ${key}");
      // new unique key will be generated every time generateSymmetricKey is run
      // [116, 89, 78, 246, 24, 145, 69, 153, 89, 21, 182, 39, 208, 83, 28, 190, 10, 254, 168, 181, 192, 9, 37, 129, 186, 197, 78, 107, 111, 196, 119, 250]

      if (key != null) {
        /*
        / Data in bytes encryption:
        */
        print("=================================================================================================================================================");
        print("Data in bytes encryption:");
        final data = [1, 2, 3];
        final sealedBox = await FlutterChacha20Poly1305.encrypt(data, key);

        print("Encrypted: ${sealedBox}");
        // Data in this object will be unique every time FlutterChacha20Poly1305.encrypt(data, key); is run
        // {
        //   encrypted: [48, 140, 193],
        //   tag: [2, 233, 22, 168, 82, 89, 110, 176, 158, 180, 147, 83, 250, 56, 15, 97],
        //   nonce: [186, 194, 249, 80, 235, 2, 210, 108, 23, 3, 133, 172] 
        // }

        // tag: authentication tag or MAC (message authentication code), the algorithm uses it to verify whether or not the ciphertext (encrypted data) and/or associated data have been modified.

        // nonce: (or "initialization vector", "IV", "salt") is a unique non-secret sequence of data required by most cipher (encryption) algorithms, making the ciphertext (encrypted data) unique despite the same key

        final encrypted = [48, 140, 193];
        final uniqueKey = [116, 89, 78, 246, 24, 145, 69, 153, 89, 21, 182, 39, 208, 83, 28, 190, 10, 254, 168, 181, 192, 9, 37, 129, 186, 197, 78, 107, 111, 196, 119, 250];
        final nonce = [186, 194, 249, 80, 235, 2, 210, 108, 23, 3, 133, 172];
        final tag = [2, 233, 22, 168, 82, 89, 110, 176, 158, 180, 147, 83, 250, 56, 15, 97];

        final decryptedData = await FlutterChacha20Poly1305.decrypt(encrypted, uniqueKey, nonce, tag);
        print("Decrypted bytes: ${decryptedData} \n\n");
        // Decrypted bytes: [1, 2, 3]

        /*
        / Data in string encryption with key, nonce, tag in base64 or hex encoding
        */

        print("=================================================================================================================================================");
        print("Data in string encryption with key, nonce, tag in base64 or hex encoding:");

        final jsonString = "{ x: 1, y: 2, z: 3 }";
        final keyInBase64 = "LAnIp48R+r525MH9kme671+2Z2sta+yRGGmA783KBl8=";
        final keyEncoding = "base64";
        final outputEncoding = "base64"; // or "hex"

        final encryptStringObject = await FlutterChacha20Poly1305.encryptString(jsonString, keyInBase64, keyEncoding, outputEncoding);
        print("String encrypted object: ${encryptStringObject}");
        // Data in this object will be unique every time FlutterChacha20Poly1305.encryptString(jsonString, keyInBase64, keyEncoding, outputEncoding) is run
        // {
        //   tag: T/dbBWayYCdN+yvOvGU61Q==,
        //   encrypted: +OxmNIVA6gvwOCoQJAalHQS4Baw=,
        //   nonce: j43/wSHX6Dh6jIAF
        // }

        final inputEncoding = "base64"; // all the params below must be in base64 encoded string
        final encryptedString = "+OxmNIVA6gvwOCoQJAalHQS4Baw=";
        final tagBase64 = "T/dbBWayYCdN+yvOvGU61Q==";
        final nonceBase64 = "j43/wSHX6Dh6jIAF";

        final decryptedJSONString = await FlutterChacha20Poly1305.decryptString(inputEncoding, encryptedString, keyInBase64, nonceBase64, tagBase64);
        print("Decrypted JSON string: ${decryptedJSONString}");
        // { x: 1, y: 2, z: 3 }
      }
    } catch (e) {
      print(e);
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Text('Running on'),
        ),
        floatingActionButton: FloatingActionButton(
          onPressed: encryptAndDecrypt,
          tooltip: 'Increment',
          child: const Icon(Icons.add),
        ), // This trailing comma makes auto-formatting nicer for build methods.
      ),
    );
  }
}
