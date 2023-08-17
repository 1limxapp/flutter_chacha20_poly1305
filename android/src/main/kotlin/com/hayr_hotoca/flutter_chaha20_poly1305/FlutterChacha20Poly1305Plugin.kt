package com.hayr_hotoca.flutter_chaha20_poly1305

import androidx.annotation.NonNull

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import com.google.crypto.tink.subtle.ChaCha20Poly1305
import org.spongycastle.util.encoders.Base64
import org.spongycastle.util.encoders.Hex

class Output(val nonce: ByteArray, val tag: ByteArray, val encrypted: ByteArray)

/** FlutterChacha20Poly1305Plugin */
class FlutterChacha20Poly1305Plugin: FlutterPlugin, MethodCallHandler {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_chacha20_poly1305")
    channel.setMethodCallHandler(this)
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    if (call.method == "encrypt") {
      encrypt(call, result)
    } else if (call.method == "encryptString") {
      encryptString(call, result)
    } else if (call.method == "decrypt") {
      decrypt(call, result)
    } else if (call.method == "decryptString") {
      decryptString(call, result)
    } else {
      result.notImplemented()
    }
  }

  private fun encrypt(call: MethodCall, result: Result) {
    try {
      val data = call.argument<ByteArray>("data")!!
      val key = call.argument<ByteArray>("key")!!

      val encryptedData = encryptData(data, key)

      result.success(
              hashMapOf(
                      "encrypted" to encryptedData.encrypted,
                      "nonce" to encryptedData.nonce,
                      "tag" to encryptedData.tag
              )
      )
    } catch (e: Exception) {
      result.error("EncryptionError", "Failed to encrypt: " + e.localizedMessage, e)
    }
  }

  private fun encryptString(call: MethodCall, result: Result) {
    try {
      val keyEncoding = call.argument<String>("keyEncoding")
      val outputEncoding = call.argument<String>("outputEncoding")
      if (keyEncoding != "base64" && keyEncoding != "hex")
        return result.error("Input encoding eror", "Input key encoding should be in 'base64' or 'hex'", null)
      if (outputEncoding != "base64" && outputEncoding != "hex")
        return result.error("Output encoding eror", "Output encoding should be in 'base64' or 'hex'", null)

      val key = call.argument<String>("key")!!
      val keyData = if (keyEncoding == "base64") Base64.decode(key) else  Hex.decode(key)

      val string = call.argument<String>("string")!!
      val plainData = string.toByteArray()

      val encryptedData = encryptData(plainData, keyData)

      result.success(
              hashMapOf(
                      "encrypted" to if (outputEncoding == "base64") Base64.toBase64String(encryptedData.encrypted) else Hex.toHexString(encryptedData.encrypted),
                      "nonce" to if (outputEncoding == "base64") Base64.toBase64String(encryptedData.nonce) else Hex.toHexString(encryptedData.nonce),
                      "tag" to if (outputEncoding == "base64") Base64.toBase64String(encryptedData.tag) else Hex.toHexString(encryptedData.tag),
              )
      )
    } catch (e: Exception) {
      result.error("EncryptionError", "Failed to encrypt string: " + e.localizedMessage, e)
    }
  }

  private fun decrypt(call: MethodCall, result: Result) {
    try {
      val encrypted = call.argument<ByteArray>("encrypted")!!
      val key = call.argument<ByteArray>("key")!!
      val nonce = call.argument<ByteArray>("nonce")!!
      val tag = call.argument<ByteArray>("tag")!!
      val cipherData = nonce + encrypted + tag

      val decrypted = decryptData(cipherData, key)

      result.success(decrypted)
    } catch  (e: Exception) {
      result.error("EncryptionError", "Failed to decrypt: " + e.localizedMessage, e)
    }
  }

  private fun decryptString(call: MethodCall, result: Result) {
    try {
      val inputEncoding = call.argument<String>("inputEncoding")
      if (inputEncoding != "base64" && inputEncoding != "hex") return result.error("Input encoding eror", "Input encoding should be in 'base64' or 'hex'", null)

      val encryptedString = call.argument<String>("encryptedString")!!
      val key = call.argument<String>("key")!!
      val keyData = if (inputEncoding == "base64") Base64.decode(key) else Hex.decode(key)
      val nonce = call.argument<String>("nonce")!!
      val tag = call.argument<String>("tag")!!
      val cipherData = if (inputEncoding == "base64")
        Base64.decode(nonce) + Base64.decode(encryptedString) + Base64.decode(tag)
      else
        Hex.decode(nonce + encryptedString + tag)

      val decrypted = decryptData(cipherData, keyData)

      result.success(decrypted.toString(Charsets.UTF_8))
    } catch  (e: Exception) {
      result.error("EncryptionError", "Failed to decrypt string: " + e.localizedMessage, e)
    }
  }

  private fun encryptData(plainData: ByteArray, keyData: ByteArray): Output {
    val cipher = ChaCha20Poly1305(keyData)
    val sealed = cipher.encrypt(plainData, null)
    val ivData = sealed.sliceArray(0..11)
    val tagData = sealed.sliceArray(sealed.size-16..sealed.size-1)
    val encryptedData = sealed.sliceArray(12..sealed.size-17)

    return Output(ivData, tagData, encryptedData)
  }

  private fun decryptData(cipherData: ByteArray, key: ByteArray): ByteArray {
    val cipher = ChaCha20Poly1305(key)
    val decrypted = cipher.decrypt(cipherData, null)

    return decrypted
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }
}
