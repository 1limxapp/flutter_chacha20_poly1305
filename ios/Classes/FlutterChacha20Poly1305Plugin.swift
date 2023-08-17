import Flutter
import UIKit
import CryptoKit

enum CryptoError: Error {
    case runtimeError(String)
}

@available(iOS 13.0, *)
public class FlutterChacha20Poly1305Plugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "flutter_chacha20_poly1305", binaryMessenger: registrar.messenger())
    let instance = FlutterChacha20Poly1305Plugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
      guard let args = call.arguments as? [String: Any] else {
          result(FlutterError(
              code: "CAUGHT_ERROR",
              message:"Invalid arguments",
              details: nil))
          return
      }
      
      do {
        switch call.method {
        case "encrypt":
            try self.encrypt(args: args, result:result)
        case "encryptString":
            try self.encryptString(args: args, result:result)
        case "decrypt":
            try self.decrypt(args: args, result:result)
        case "decryptString":
            try self.decryptString(args: args, result:result)
        default:
            result(FlutterMethodNotImplemented)
        }
      } catch let error as NSError {
          result(FlutterError(
              code: "CAUGHT_ERROR",
              message:"\(error.domain), \(error.code), \(error.description)",
              details: nil))
      } catch {
          result(FlutterError(
              code: "CAUGHT_ERROR",
              message:"\(error)",
              details: nil))
      }
  }
    
    private func encryptData(plainData: Data, key: Data) throws -> ChaChaPoly.SealedBox {
        let skey = SymmetricKey(data: key)
        return try ChaChaPoly.seal(plainData, using: skey)
    }

    private func decryptData(cipherData: Data, keyData: Data, nonceData: Data, tagData: Data) throws -> Data {
        let skey = SymmetricKey(data: keyData)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonceData),
                                               ciphertext: cipherData,
                                               tag: tagData)
        let decryptedData = try ChaChaPoly.open(sealedBox, using: skey)
        return decryptedData
    }

    private func encrypt(args: [String: Any], result: @escaping FlutterResult) throws {
        do {
            guard let data = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            guard let key = (args["key"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "key"))
                return
            }

            let sealed = try self.encryptData(plainData: data, key: key)

            result([
                "encrypted": FlutterStandardTypedData(bytes: sealed.ciphertext),
                "tag": FlutterStandardTypedData(bytes: sealed.tag),
                "nonce": FlutterStandardTypedData(bytes: sealed.nonce.withUnsafeBytes {
                    Data(Array($0))
                }),
            ])
        } catch CryptoError.runtimeError(let errorMessage) {
            result(FlutterError(code: "InvalidArgumentError", message: errorMessage.localizedLowercase, details: nil))
        } catch {
            result(FlutterError(code: "EncryptionError", message:"Failed to encrypt: " + error.localizedDescription, details: nil))
        }
    }
    
    private func encryptString(args: [String: Any], result: @escaping FlutterResult) throws {
        do {
            guard let keyEncoding = args["keyEncoding"] as? String else {
                result(parameterError(name: "keyEncoding"))
                return
            }

            guard let outputEncoding = args["outputEncoding"] as? String else {
                result(parameterError(name: "outputEncoding"))
                return
            }
            
            
            if (keyEncoding != "base64" && keyEncoding != "hex") {
                result(FlutterError(code: "Input encoding eror", message: "Input key encoding should be in 'base64' or 'hex'", details: nil))
                return
            }

            if (outputEncoding != "base64" && outputEncoding != "hex") {
                result(FlutterError(code: "Output encoding eror", message: "Output encoding should be in 'base64' or 'hex'", details: nil))
                return
            }

            guard let key = args["key"] as? String else {
                result(parameterError(name: "key"))
                return
            }
            
            guard let string = args["string"] as? String else {
                result(parameterError(name: "string"))
                return
            }
            
            let keyData = keyEncoding == "base64" ? Data(base64Encoded: key)! : Data(hexString: key)!
            let plainData = string.data(using: .utf8)!

            let sealed = try self.encryptData(plainData: plainData, key: keyData)
            
            let encrypted = outputEncoding == "base64" ? sealed.ciphertext.base64EncodedString() : sealed.ciphertext.hexadecimal
            let nonce = outputEncoding == "base64" ? sealed.nonce.withUnsafeBytes {
                Data(Array($0)).base64EncodedString()
            } : sealed.nonce.withUnsafeBytes {
                Data(Array($0)).hexadecimal
            }
            let tag = outputEncoding == "base64" ? sealed.tag.base64EncodedString() : sealed.tag.hexadecimal

            result([
                "encrypted": encrypted,
                "tag": tag,
                "nonce": nonce,
            ])
        } catch CryptoError.runtimeError(let errorMessage) {
            result(FlutterError(code: "InvalidArgumentError", message: errorMessage.localizedLowercase, details: nil))
        } catch {
            result(FlutterError(code: "EncryptionError", message:"Failed to encrypt string: " + error.localizedDescription, details: nil))
        }
    }

    private func decrypt(args: [String: Any], result: @escaping FlutterResult) throws {
        do {
            guard let cipherData = (args["encrypted"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "encrypted"))
                return
            }
            guard let key = (args["key"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "key"))
                return
            }
            guard let nonce = (args["nonce"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "nonce"))
                return
            }
            guard let tag = (args["tag"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "tag"))
                return
            }

            let decryptedData = try decryptData(cipherData: cipherData, keyData: key, nonceData: nonce, tagData: tag)
            
            result(FlutterStandardTypedData(bytes: decryptedData))
            
        } catch CryptoError.runtimeError(let errorMessage) {
            result(FlutterError(code: "InvalidArgumentError", message: errorMessage.localizedLowercase, details: nil))
        } catch {
            result(FlutterError(code: "EncryptionError", message:"Failed to decrypt: " + error.localizedDescription, details: nil))
        }
    }
    
    private func decryptString(args: [String: Any], result: @escaping FlutterResult) throws {
        do {
            guard let inputEncoding = args["inputEncoding"] as? String else {
                result(parameterError(name: "inputEncoding"))
                return
            }
            
            if (inputEncoding != "base64" && inputEncoding != "hex") {
                result(FlutterError(code: "Input encoding eror", message: "Input key encoding should be in 'base64' or 'hex'", details: nil))
                return
            }
        
            guard let encryptedString = args["encryptedString"] as? String else {
                result(parameterError(name: "encryptedString"))
                return
            }
            guard let key = args["key"] as? String else {
                result(parameterError(name: "key"))
                return
            }
            guard let nonce = args["nonce"] as? String else {
                result(parameterError(name: "nonce"))
                return
            }
            guard let tag = args["tag"] as? String else {
                result(parameterError(name: "tag"))
                return
            }
            
            let cipherData = inputEncoding == "base64" ? Data(base64Encoded: encryptedString)! : Data(hexString: encryptedString)!
            let keyData = inputEncoding == "base64" ? Data(base64Encoded: key)! : Data(hexString: key)!
            let nonceData = inputEncoding == "base64" ? Data(base64Encoded: nonce)! : Data(hexString: nonce)!
            let tagData = inputEncoding == "base64" ? Data(base64Encoded: tag)! : Data(hexString: tag)!

            let decryptedData = try decryptData(cipherData: cipherData, keyData: keyData, nonceData: nonceData, tagData: tagData)
            
            result(String(decoding: decryptedData, as: UTF8.self))
            
        } catch CryptoError.runtimeError(let errorMessage) {
            result(FlutterError(code: "InvalidArgumentError", message: errorMessage.localizedLowercase, details: nil))
        } catch {
            result(FlutterError(code: "EncryptionError", message:"Failed to decrypt: " + error.localizedDescription, details: nil))
        }
    }
    
    private func parameterError(name: String) -> FlutterError {
        return FlutterError(code: "INVALID_ARGUMENT", message: "Parameter '\(name)' is missing or invalid", details: nil)
    }
}
