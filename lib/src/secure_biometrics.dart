import 'dart:convert';
import 'dart:math' show Random;

import 'package:asn1lib/asn1lib.dart';
import 'package:flutter/foundation.dart';
import 'package:local_auth/local_auth.dart';
import 'package:pointycastle/export.dart';
import 'package:secure_biometrics/src/config.dart';
import 'package:secure_biometrics/src/constants.dart';
import 'package:secure_biometrics/src/errors/secure_biometric_exception.dart';
import 'package:secure_biometrics/src/helper.dart';

/// {@template secure_biometrics}
/// A Very Good Project created by Very Good CLI.
/// {@endtemplate}
class SecureBiometrics {
  // private constructor
  SecureBiometrics._({
    StorageHelper? storageHelper,
    LocalAuthentication? localAuth,
  })  : _storage = storageHelper ?? StorageHelper(),
        _localAuth = localAuth ?? LocalAuthentication();

  /// {@macro secure_biometrics}
  /// instance that should be used throughout the app
  static final SecureBiometrics instance = SecureBiometrics._();

  /// For testing purposes
  @visibleForTesting
  // ignore: prefer_constructors_over_static_methods
  static SecureBiometrics createInstance({
    required StorageHelper storageHelper,
    required LocalAuthentication localAuth,
  }) {
    return SecureBiometrics._(
      storageHelper: storageHelper,
      localAuth: localAuth,
    );
  }

  final StorageHelper _storage;
  final LocalAuthentication _localAuth;

  /// method to generate RSA
  /// key pair
  Future<KeyPair> generateKeyPair() async {
    try {
      final secureRandom = FortunaRandom();

      final seedSource = Random.secure();
      final seeds = List<int>.generate(32, (i) => seedSource.nextInt(256));
      secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

      final keyGen = RSAKeyGenerator()
        ..init(
          ParametersWithRandom(
            RSAKeyGeneratorParameters(
              BigInt.parse(Constants.publicExponent),
              Constants.defaultKeySize,
              64,
            ),
            secureRandom,
          ),
        );

      final pair = keyGen.generateKeyPair();
      final publicKey = pair.publicKey as RSAPublicKey;
      final privateKey = pair.privateKey as RSAPrivateKey;
      await _storeKeyPair(privateKey: privateKey);

      return KeyPair(privateKey: privateKey, publicKey: publicKey);
    } catch (e) {
      throw KeyOperationException('Failed to generate key pair: $e');
    }
  }

  /// Signs data using the stored private key
  Future<Uint8List?> signData({
    required String data,
    required RSAPrivateKey privateKey,
  }) async {
    try {
      final finalKey = privateKey;
      final signer = RSASigner(SHA256Digest(), Constants.padding)
        ..init(true, PrivateKeyParameter<RSAPrivateKey>(finalKey));

      final dataToSign = Uint8List.fromList(utf8.encode(data));
      final signature = signer.generateSignature(dataToSign);

      return signature.bytes;
    } catch (e) {
      if (e is SecureBiometricException) rethrow;
      throw KeyOperationException('Failed to sign data: $e');
    }
  }

  /// check if private key exists in storage
  Future<bool> hasKey() async {
    try {
      final key = await getPrivateKey();
      return key != null;
    } catch (e) {
      if (e is SecureBiometricException) rethrow;
      throw KeyOperationException('Failed to fetch key: $e');
    }
  }

  @visibleForTesting

  ///verify signed transaction
  Future<bool> verifySignature(
    String data,
    Uint8List signature, {
    RSAPublicKey? key,
  }) async {
    try {
      final publicKey = await _getPublicKey();
      if (publicKey == null && key == null) {
        throw const KeyNotFoundException('Public');
      }
      final finalKey = key ?? publicKey!;
      final verifier = RSASigner(SHA256Digest(), Constants.padding)
        ..init(false, PublicKeyParameter<RSAPublicKey>(finalKey));

      final dataToVerify = Uint8List.fromList(utf8.encode(data));

      try {
        return verifier.verifySignature(dataToVerify, RSASignature(signature));
      } catch (e) {
        return false;
      }
    } catch (e) {
      if (e is SecureBiometricException) rethrow;
      throw KeyOperationException('Failed to verify signature: $e');
    }
  }

  /// Retrieves the number of failed biometric attempts
  Future<int> retrieveFailedAttempts() async {
    try {
      final attempts = await _storage.retrieveData(key: StorageKeys.attempts);
      return int.tryParse(attempts ?? '0') ?? 0;
    } catch (e) {
      throw StorageException('Failed to retrieve failed attempts: $e');
    }
  }

  /// validate user biometric
  Future<bool> _validateBiometric() async {
    try {
      final failedAttempts = await retrieveFailedAttempts();
      if (failedAttempts >= Constants.maxAttempts) {
        throw const MaxAttemptsExceededException();
      }

      final canAuthenticate = await _localAuth.canCheckBiometrics;
      if (!canAuthenticate) {
        throw const BiometricNotAvailableException();
      }

      final didAuthenticate = await _localAuth.authenticate(
        localizedReason: 'Please authenticate to sign transaction',
        options: const AuthenticationOptions(biometricOnly: true),
      );

      if (!didAuthenticate) {
        await _incrementFailedAttempts();
        throw const BiometricAuthenticationException('Authentication failed');
      }

      await _resetFailedAttempts();
      return true;
    } catch (e) {
      await _incrementFailedAttempts();
      if (e is SecureBiometricException) rethrow;
      throw BiometricAuthenticationException(e.toString());
    }
  }

  /// Store generated RSA keypair
  /// for test cases
  Future<bool> _storeKeyPair({
    required RSAPrivateKey privateKey,
    RSAPublicKey? publicKey,
  }) async {
    try {
      if (publicKey != null) {
        final publicKeyJson = {
          'modulus': publicKey.modulus.toString(),
          'exponent': publicKey.exponent.toString(),
        };
        await _storage.storeData(
          key: StorageKeys.publicKey,
          data: jsonEncode(publicKeyJson),
        );
      }

      final privateKeyJson = {
        'modulus': privateKey.modulus.toString(),
        'privateExponent': privateKey.privateExponent.toString(),
        'p': privateKey.p.toString(),
        'q': privateKey.q.toString(),
      };

      await _storage.storeData(
        key: StorageKeys.privateKey,
        data: jsonEncode(privateKeyJson),
      );
      return true;
    } catch (e) {
      throw StorageException('Failed to store key pair: $e');
    }
  }

  /// retrieved stored private key
  Future<RSAPrivateKey?> authenticateUser() async {
    try {
      final permission = await _validateBiometric();
      if (!permission) {
        throw const BiometricAuthenticationException(
          'Biometric validation is necessary to fetch key',
        );
      }

      final privateKeyStr =
          await _storage.retrieveData(key: StorageKeys.privateKey);
      if (privateKeyStr == null) return null;

      final privateKeyJson = jsonDecode(privateKeyStr) as Map<String, dynamic>;
      return RSAPrivateKey(
        BigInt.parse(privateKeyJson['modulus'] as String),
        BigInt.parse(privateKeyJson['privateExponent'] as String),
        BigInt.parse(privateKeyJson['p'] as String),
        BigInt.parse(privateKeyJson['q'] as String),
      );
    } catch (e) {
      if (e is SecureBiometricException) rethrow;
      throw KeyOperationException('Failed to retrieve private key: $e');
    }
  }

  /// retrieve private key if it exists for test
  /// purposes only
  @visibleForTesting
  Future<RSAPrivateKey?> getPrivateKey() async {
    try {
      final privateKeyStr =
          await _storage.retrieveData(key: StorageKeys.privateKey);
      if (privateKeyStr == null) return null;

      final privateKeyJson = jsonDecode(privateKeyStr) as Map<String, dynamic>;
      return RSAPrivateKey(
        BigInt.parse(privateKeyJson['modulus'] as String),
        BigInt.parse(privateKeyJson['privateExponent'] as String),
        BigInt.parse(privateKeyJson['p'] as String),
        BigInt.parse(privateKeyJson['q'] as String),
      );
    } catch (e) {
      if (e is SecureBiometricException) rethrow;
      throw KeyOperationException('Failed to retrieve private key: $e');
    }
  }

  /// retrieve public key if it exists for test
  /// purposes only
  Future<RSAPublicKey?> _getPublicKey() async {
    try {
      final publicKeyStr =
          await _storage.retrieveData(key: StorageKeys.publicKey);
      if (publicKeyStr == null) return null;

      final publicKeyJson = jsonDecode(publicKeyStr) as Map<String, dynamic>;
      return RSAPublicKey(
        BigInt.parse(publicKeyJson['modulus'] as String),
        BigInt.parse(publicKeyJson['exponent'] as String),
      );
    } catch (e) {
      throw KeyOperationException('Failed to retrieve public key: $e');
    }
  }

  Future<void> _incrementFailedAttempts() async {
    try {
      final current = await retrieveFailedAttempts();
      await _storage.storeData(
        key: StorageKeys.attempts,
        data: (current + 1).toString(),
      );
    } catch (e) {
      throw StorageException('Failed to increment failed attempts: $e');
    }
  }

  /// Stores the number of failed biometric attempts
  Future<void> _resetFailedAttempts() async {
    try {
      await _storage.storeData(
        key: StorageKeys.attempts,
        data: '0',
      );
    } catch (e) {
      throw StorageException('Failed to reset failed attempts: $e');
    }
  }

  /// exports PEM-encoded public key
  Future<String> exportPublicKeyPEM() async {
    try {
      final publicKey = await _getPublicKey();
      if (publicKey == null) {
        throw const KeyNotFoundException('Public');
      }

      final topLevelSeq = ASN1Sequence();
      final algorithmSeq = ASN1Sequence()
        ..add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        ..add(ASN1Null());
      topLevelSeq.add(algorithmSeq);

      final publicKeySeq = ASN1Sequence()
        ..add(ASN1Integer(publicKey.modulus!))
        ..add(ASN1Integer(publicKey.exponent!));

      final publicKeyBitString = ASN1BitString(publicKeySeq.encodedBytes);
      topLevelSeq.add(publicKeyBitString);

      final derBytes = topLevelSeq.encodedBytes;
      final base64Encoded = base64.encode(derBytes);
      final lines = base64Encoded.replaceAllMapped(
        RegExp('.{64}'),
        (match) => '${match.group(0)}\n',
      );

      return '-----BEGIN PUBLIC KEY-----\n$lines-----END PUBLIC KEY-----';
    } catch (e) {
      if (e is SecureBiometricException) rethrow;
      throw PEMException('Failed to export public key to PEM: $e');
    }
  }

  /// Verifies a PEM-encoded public key string
  /// Returns true if the format is valid, false otherwise
  @visibleForTesting
  static bool verifyPEMFormat(String pem) {
    try {
      if (!pem.startsWith('-----BEGIN PUBLIC KEY-----') ||
          !pem.endsWith('-----END PUBLIC KEY-----')) {
        return false;
      }

      final pemContent = pem
          .replaceFirst('-----BEGIN PUBLIC KEY-----', '')
          .replaceFirst('-----END PUBLIC KEY-----', '')
          .replaceAll(RegExp(r'\s+'), '');

      final derBytes = base64.decode(pemContent);
      final parser = ASN1Parser(derBytes);
      final topLevelSeq = parser.nextObject() as ASN1Sequence;

      if (topLevelSeq.elements.length != 2) return false;

      final algorithmSeq = topLevelSeq.elements[0] as ASN1Sequence;
      if (algorithmSeq.elements.length != 2) return false;

      final algorithmOid = algorithmSeq.elements[0] as ASN1ObjectIdentifier;
      final algorithmParams = algorithmSeq.elements[1];

      if (algorithmOid.identifier != '1.2.840.113549.1.1.1') return false;
      if (algorithmParams is! ASN1Null) return false;

      final publicKeyBits = topLevelSeq.elements[1] as ASN1BitString;
      final publicKeyParser = ASN1Parser(publicKeyBits.contentBytes());
      final publicKeySeq = publicKeyParser.nextObject() as ASN1Sequence;

      if (publicKeySeq.elements.length != 2) return false;

      return true;
    } catch (e) {
      return false;
    }
  }

  /// Parses a PEM-encoded public key string back to RSAPublicKey
  /// Throws FormatException if the PEM is invalid
  @visibleForTesting
  static Future<RSAPublicKey> parsePEM(String pem) async {
    if (!verifyPEMFormat(pem)) {
      throw const PEMException('Invalid PEM format');
    }

    try {
      final pemContent = pem
          .replaceFirst('-----BEGIN PUBLIC KEY-----', '')
          .replaceFirst('-----END PUBLIC KEY-----', '')
          .replaceAll(RegExp(r'\s+'), '');

      final derBytes = base64.decode(pemContent);
      final parser = ASN1Parser(derBytes);
      final topLevelSeq = parser.nextObject() as ASN1Sequence;
      final publicKeyBits = topLevelSeq.elements[1] as ASN1BitString;
      final publicKeyParser = ASN1Parser(publicKeyBits.contentBytes());
      final publicKeySeq = publicKeyParser.nextObject() as ASN1Sequence;

      final modulus =
          (publicKeySeq.elements[0] as ASN1Integer).valueAsBigInteger;
      final exponent =
          (publicKeySeq.elements[1] as ASN1Integer).valueAsBigInteger;

      return RSAPublicKey(modulus, exponent);
    } catch (e) {
      throw PEMException('Error parsing PEM: $e');
    }
  }

  /// Verifies that exported PEM matches the original public key
  @visibleForTesting
  Future<bool> verifyExportedPEM() async {
    try {
      final pem = await exportPublicKeyPEM();
      if (!verifyPEMFormat(pem)) return false;

      final originalKey = await _getPublicKey();
      if (originalKey == null) return false;

      final parsedKey = await parsePEM(pem);

      return originalKey.modulus == parsedKey.modulus &&
          originalKey.exponent == parsedKey.exponent;
    } catch (e) {
      if (e is SecureBiometricException) rethrow;
      throw PEMException('Failed to verify exported PEM: $e');
    }
  }
}
