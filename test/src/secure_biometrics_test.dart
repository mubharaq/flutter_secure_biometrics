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
    registerFallbackValue(const AuthenticationOptions(biometricOnly: true));

    when(
      () => mockStorage.storeData(
        key: any(named: 'key'),
        data: any(named: 'data'),
      ),
    ).thenAnswer((_) async {});

    secureBiometrics = SecureBiometrics.createInstance(
      storageHelper: mockStorage,
      localAuth: mockLocalAuth,
    );

    // Generate the key pair for use in tests
    final keyPair = await secureBiometrics.generateKeyPair();
    testPrivateKey = keyPair.privateKey;
    testPublicKey = keyPair.publicKey;
  });

  group('Key Generation and Storage', () {
    setUp(() {
      when(
        () => mockStorage.storeData(
          key: any(named: 'key'),
          data: any(named: 'data'),
        ),
      ).thenAnswer((_) async {});
    });

    test(
        '''generateKeyPair should create valid RSA key pair and store private key''',
        () async {
      final keyPair = await secureBiometrics.generateKeyPair();

      expect(keyPair.privateKey, isA<RSAPrivateKey>());
      expect(keyPair.publicKey, isA<RSAPublicKey>());
      expect(keyPair.privateKey.modulus, isNotNull);
      expect(keyPair.publicKey.modulus, isNotNull);

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

    test('generateKeyPair should throw on storage failure', () async {
      when(
        () => mockStorage.storeData(
          key: any(named: 'key'),
          data: any(named: 'data'),
        ),
      ).thenThrow(Exception('Storage failure'));

      expect(
        () => secureBiometrics.generateKeyPair(),
        throwsA(isA<KeyOperationException>()),
      );
    });
  });

  group('Private Key Operations', () {
    test('getPrivateKey should return null when storage is empty', () async {
      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer((_) async => null);

      final key = await secureBiometrics.getPrivateKey();
      expect(key, isNull);
    });

    test('getPrivateKey should throw on invalid stored data', () async {
      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer((_) async => 'invalid json');

      expect(
        () => secureBiometrics.getPrivateKey(),
        throwsA(isA<KeyOperationException>()),
      );
    });

    test('getPrivateKey should return valid key when properly stored',
        () async {
      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPrivateKey.modulus.toString(),
          'privateExponent': testPrivateKey.privateExponent.toString(),
          'p': testPrivateKey.p.toString(),
          'q': testPrivateKey.q.toString(),
        }),
      );

      final key = await secureBiometrics.getPrivateKey();
      expect(key, isNotNull);
      expect(key!.modulus, equals(testPrivateKey.modulus));
    });
  });

  group('Biometric Authentication', () {
    setUp(() {
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

      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPrivateKey.modulus.toString(),
          'privateExponent': testPrivateKey.privateExponent.toString(),
          'p': testPrivateKey.p.toString(),
          'q': testPrivateKey.q.toString(),
        }),
      );
    });

    test('authenticateUser should succeed with proper authentication',
        () async {
      final result = await secureBiometrics.authenticateUser();
      expect(result, isNotNull);
      expect(result!.modulus, equals(testPrivateKey.modulus));
    });

    test('authenticateUser should fail when biometrics unavailable', () async {
      when(() => mockLocalAuth.canCheckBiometrics)
          .thenAnswer((_) async => false);

      expect(
        () => secureBiometrics.authenticateUser(),
        throwsA(isA<BiometricNotAvailableException>()),
      );
    });

    test('authenticateUser should fail after max attempts', () async {
      when(() => mockStorage.retrieveData(key: StorageKeys.attempts))
          .thenAnswer((_) async => Constants.maxAttempts.toString());

      expect(
        () => secureBiometrics.authenticateUser(),
        throwsA(isA<MaxAttemptsExceededException>()),
      );
    });
  });

  group('Signing and Verification', () {
    late RSAPrivateKey storedKey;

    setUp(() async {
      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPrivateKey.modulus.toString(),
          'privateExponent': testPrivateKey.privateExponent.toString(),
          'p': testPrivateKey.p.toString(),
          'q': testPrivateKey.q.toString(),
        }),
      );

      when(() => mockStorage.retrieveData(key: StorageKeys.publicKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPublicKey.modulus.toString(),
          'exponent': testPublicKey.exponent.toString(),
        }),
      );

      // Get the key before each test
      final key = await secureBiometrics.getPrivateKey();
      expect(
        key,
        isNotNull,
        reason: 'Private key should be available for signing tests',
      );
      storedKey = key!;
    });

    const testData = 'test data to sign';

    test('should successfully sign and verify data', () async {
      final signedData = await secureBiometrics.signData(
        data: testData,
        privateKey: storedKey,
      );
      expect(signedData, isNotNull);

      final isValid = await secureBiometrics.verifySignature(
        testData,
        signedData!,
      );
      expect(isValid, true);
    });

    test('should fail verification with tampered data', () async {
      final signedData = await secureBiometrics.signData(
        data: testData,
        privateKey: storedKey,
      );
      expect(signedData, isNotNull);

      final isValid = await secureBiometrics.verifySignature(
        'tampered data',
        signedData!,
      );
      expect(isValid, false);
    });

    test('should throw on signing with bad key', () async {
      expect(
        () => secureBiometrics.signData(
          data: testData,
          privateKey: '' as RSAPrivateKey,
        ),
        throwsA(isA<TypeError>()),
      );
    });
  });

  group('PEM Format and Parsing Tests', () {
    late String validPem;

    setUp(() {
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

      expect(validPem.trim().startsWith('-----BEGIN PUBLIC KEY-----'), isTrue);
      expect(validPem.trim().endsWith('-----END PUBLIC KEY-----'), isTrue);

      final pemContent = validPem
          .replaceFirst('-----BEGIN PUBLIC KEY-----', '')
          .replaceFirst('-----END PUBLIC KEY-----', '')
          .trim()
          .replaceAll(RegExp(r'\s+'), '');

      expect(() => base64.decode(pemContent), returnsNormally);
    });

    test('exportPublicKeyPEM should throw when public key not found', () async {
      when(() => mockStorage.retrieveData(key: StorageKeys.publicKey))
          .thenAnswer((_) async => null);

      expect(
        () => secureBiometrics.exportPublicKeyPEM(),
        throwsA(isA<KeyNotFoundException>()),
      );
    });

    test('verifyPEMFormat should validate correct RSA structure', () async {
      validPem = await secureBiometrics.exportPublicKeyPEM();

      validPem = validPem
          .split('\n')
          .map((line) => line.trim())
          .where((line) => line.isNotEmpty)
          .join('\n');

      expect(SecureBiometrics.verifyPEMFormat(validPem), isTrue);
    });

    test('parsePEM should correctly reconstruct public key', () async {
      validPem = await secureBiometrics.exportPublicKeyPEM();

      validPem = validPem
          .split('\n')
          .map((line) => line.trim())
          .where((line) => line.isNotEmpty)
          .join('\n');

      final parsedKey = await SecureBiometrics.parsePEM(validPem);
      expect(parsedKey.modulus, equals(testPublicKey.modulus));
      expect(parsedKey.exponent, equals(testPublicKey.exponent));
    });

    test('parsePEM should throw PEMException for invalid PEM', () {
      expect(
        () => SecureBiometrics.parsePEM('invalid content'),
        throwsA(isA<PEMException>()),
      );
    });
  });

  group('End-to-End Key Operation Tests', () {
    late RSAPrivateKey storedKey;

    setUp(() async {
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

      when(() => mockStorage.retrieveData(key: StorageKeys.privateKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPrivateKey.modulus.toString(),
          'privateExponent': testPrivateKey.privateExponent.toString(),
          'p': testPrivateKey.p.toString(),
          'q': testPrivateKey.q.toString(),
        }),
      );

      when(() => mockStorage.retrieveData(key: StorageKeys.publicKey))
          .thenAnswer(
        (_) async => jsonEncode({
          'modulus': testPublicKey.modulus.toString(),
          'exponent': testPublicKey.exponent.toString(),
        }),
      );

      // Get the key before each test
      final key = await secureBiometrics.getPrivateKey();
      expect(
        key,
        isNotNull,
        reason: 'Private key should be available for e2e tests',
      );
      storedKey = key!;
    });

    const testMessage = 'Test message for signing';

    test('should successfully perform sign-export-parse-verify cycle',
        () async {
      final signature = await secureBiometrics.signData(
        data: testMessage,
        privateKey: storedKey,
      );
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
      final signature = await secureBiometrics.signData(
        data: testMessage,
        privateKey: storedKey,
      );
      expect(signature, isNotNull);

      final verificationResult = await secureBiometrics.verifySignature(
        'Wrong message',
        signature!,
      );
      expect(verificationResult, false);
    });
  });
}
