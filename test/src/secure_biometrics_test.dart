import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:local_auth/local_auth.dart';
import 'package:mocktail/mocktail.dart';
import 'package:pointycastle/export.dart';

import 'package:secure_biometrics/secure_biometrics.dart';
import 'package:secure_biometrics/src/constants.dart';
import 'package:secure_biometrics/src/helper.dart';

class MockStorageHelper extends Mock implements StorageHelper {}

class MockLocalAuthentication extends Mock implements LocalAuthentication {}

void main() {
  late SecureBiometrics secureBiometrics;
  late MockStorageHelper mockStorage;
  late MockLocalAuthentication mockLocalAuth;
  late RSAPrivateKey testPrivateKey;
  late RSAPublicKey testPublicKey;

  setUpAll(() async {
    mockStorage = MockStorageHelper();
    mockLocalAuth = MockLocalAuthentication();

    secureBiometrics = SecureBiometrics.createInstance(
      storageHelper: mockStorage,
      localAuth: mockLocalAuth,
    );

    final keyPair = await secureBiometrics.generateKeyPair();
    testPrivateKey = keyPair.privateKey;
    testPublicKey = keyPair.publicKey;
    registerFallbackValue(const AuthenticationOptions(biometricOnly: true));
  });

  group('Key Generation and Storage', () {
    test('generateKeyPair should create valid RSA key pair', () async {
      final keyPair = await secureBiometrics.generateKeyPair();

      expect(keyPair.privateKey, isA<RSAPrivateKey>());
      expect(keyPair.publicKey, isA<RSAPublicKey>());
      expect(keyPair.privateKey.modulus, isNotNull);
      expect(keyPair.publicKey.modulus, isNotNull);
    });

    test('storeKeyPair should properly serialize and store keys', () async {
      when(
        () => mockStorage.storeData(
          key: any(named: 'key'),
          data: any(named: 'data'),
        ),
      ).thenAnswer((_) async => true);

      final result = await secureBiometrics.storeKeyPair(
        privateKey: testPrivateKey,
        publicKey: testPublicKey,
      );

      expect(result, true);
      verify(
        () => mockStorage.storeData(
          key: StorageKeys.privateKey,
          data: any(
            that: contains(testPrivateKey.modulus.toString()),
            named: 'data',
          ),
        ),
      ).called(1);
    });
  });

  group('Biometric Authentication', () {
    test('validateBiometric should succeed with proper authentication',
        () async {
      when(() => mockStorage.retrieveData(key: StorageKeys.attempts))
          .thenAnswer((_) async => '0');
      when(() => mockLocalAuth.canCheckBiometrics)
          .thenAnswer((_) async => true);
      when(
        () => mockLocalAuth.authenticate(
          localizedReason: any(named: 'localizedReason'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async => true);
      when(
        () => mockStorage.storeData(
          key: any(named: 'key'),
          data: any(named: 'data'),
        ),
      ).thenAnswer((_) async {});

      final result = await secureBiometrics.validateBiometric();
      expect(result, true);
    });

    test('validateBiometric should fail after 3 attempts', () async {
      when(() => mockStorage.retrieveData(key: StorageKeys.attempts))
          .thenAnswer((_) async => '3');

      expect(
        () => secureBiometrics.validateBiometric(),
        throwsException,
      );
    });
  });

  group('Signing and Verification', () {
    setUp(() {
      // 1. Set up validateBiometric prerequisites
      when(() => mockStorage.retrieveData(key: StorageKeys.attempts))
          .thenAnswer((_) async => '0'); // For failed attempts check
      when(() => mockLocalAuth.canCheckBiometrics)
          .thenAnswer((_) async => true);
      when(
        () => mockLocalAuth.authenticate(
          localizedReason: any(named: 'localizedReason'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async => true);
      when(
        () => mockStorage.storeData(
          key: any(named: 'key'),
          data: any(named: 'data'),
        ),
      ).thenAnswer((_) async {});
      // 2. Set up private key retrieval
      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPrivateKey.modulus.toString(),
          'privateExponent': testPrivateKey.privateExponent.toString(),
          'p': testPrivateKey.p.toString(),
          'q': testPrivateKey.q.toString(),
        }),
      );

      // 3. Set up public key retrieval for verification
      when(() => mockStorage.retrieveData(key: StorageKeys.publicKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPublicKey.modulus.toString(),
          'exponent': testPublicKey.exponent.toString(),
        }),
      );
    });
    const testData = 'test data to sign';

    test('should successfully sign and verify data', () async {
      final signedData = await secureBiometrics.signData(testData);
      expect(signedData, isNotNull);

      final isValid = await secureBiometrics.verifySignature(
        testData,
        signedData!,
      );
      expect(isValid, true);
    });

    test('should fail verification with tampered data', () async {
      final signedData = await secureBiometrics.signData(testData);
      expect(signedData, isNotNull);

      final isValid = await secureBiometrics.verifySignature(
        'tampered data',
        signedData!,
      );
      expect(isValid, false);
    });
  });

  group('PEM Format and Parsing Tests', () {
    late String validPem;

    setUp(() {
      // Mock storage to return the public key
      when(() => mockStorage.retrieveData(key: StorageKeys.publicKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPublicKey.modulus.toString(),
          'exponent': testPublicKey.exponent.toString(),
        }),
      );
    });

    test('exportPublicKeyPEM should generate valid PEM format', () async {
      validPem = await secureBiometrics.exportPublicKeyPEM();

      // More detailed PEM structure verification
      expect(validPem.trim().startsWith('-----BEGIN PUBLIC KEY-----'), isTrue);
      expect(validPem.trim().endsWith('-----END PUBLIC KEY-----'), isTrue);

      // Extract and verify base64 content
      final pemContent = validPem
          .replaceFirst('-----BEGIN PUBLIC KEY-----', '')
          .replaceFirst('-----END PUBLIC KEY-----', '')
          .trim()
          .replaceAll(RegExp(r'\s+'), '');

      expect(() => base64.decode(pemContent), returnsNormally);
    });

    test('verifyPEMFormat should validate correct RSA structure', () async {
      validPem = await secureBiometrics.exportPublicKeyPEM();

      // Clean up the PEM format by removing extra whitespace
      validPem = validPem
          .split('\n')
          .map((line) => line.trim())
          .where((line) => line.isNotEmpty)
          .join('\n');

      expect(SecureBiometrics.verifyPEMFormat(validPem), isTrue);
    });

    test('parsePEM should correctly reconstruct public key', () async {
      validPem = await secureBiometrics.exportPublicKeyPEM();

      // Clean up the PEM format
      validPem = validPem
          .split('\n')
          .map((line) => line.trim())
          .where((line) => line.isNotEmpty)
          .join('\n');

      final parsedKey = await SecureBiometrics.parsePEM(validPem);
      expect(parsedKey.modulus, equals(testPublicKey.modulus));
      expect(parsedKey.exponent, equals(testPublicKey.exponent));
    });

    test('parsePEM should throw SecureBiometricsException for invalid PEM', () {
      expect(
        () => SecureBiometrics.parsePEM('invalid content'),
        throwsA(isA<SecureBiometricException>()),
      );
    });
  });

  group('End-to-End Key Operation Tests', () {
    setUp(() {
      // 1. Set up validateBiometric prerequisites
      when(() => mockStorage.retrieveData(key: StorageKeys.attempts))
          .thenAnswer((_) async => '0'); // For failed attempts check
      when(() => mockLocalAuth.canCheckBiometrics)
          .thenAnswer((_) async => true);
      when(
        () => mockLocalAuth.authenticate(
          localizedReason: any(named: 'localizedReason'),
          options: any(named: 'options'),
        ),
      ).thenAnswer((_) async => true);
      when(
        () => mockStorage.storeData(
          key: any(named: 'key'),
          data: any(named: 'data'),
        ),
      ).thenAnswer((_) async {});
      // 2. Set up private key retrieval
      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPrivateKey.modulus.toString(),
          'privateExponent': testPrivateKey.privateExponent.toString(),
          'p': testPrivateKey.p.toString(),
          'q': testPrivateKey.q.toString(),
        }),
      );

      // 3. Set up public key retrieval for verification
      when(() => mockStorage.retrieveData(key: StorageKeys.publicKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPublicKey.modulus.toString(),
          'exponent': testPublicKey.exponent.toString(),
        }),
      );
    });
    const testMessage = 'Test message for signing';

    test('should successfully perform sign-export-parse-verify cycle',
        () async {
      final signature = await secureBiometrics.signData(testMessage);
      expect(signature, isNotNull);

      final pem = await secureBiometrics.exportPublicKeyPEM();
      expect(SecureBiometrics.verifyPEMFormat(pem), isTrue);

      final parsedKey = await SecureBiometrics.parsePEM(pem);
      expect(parsedKey.modulus, equals(testPublicKey.modulus));
      expect(parsedKey.exponent, equals(testPublicKey.exponent));

      final verificationResult = await secureBiometrics.verifySignature(
        testMessage,
        signature!,
      );
      expect(verificationResult, isTrue);
    });

    test('signature verification should fail with wrong message', () async {
      final signature = await secureBiometrics.signData(testMessage);
      expect(signature, isNotNull);

      final verificationResult = await secureBiometrics.verifySignature(
        'Wrong message',
        signature!,
      );
      expect(verificationResult, isFalse);
    });
  });
}
