import 'package:pointycastle/pointycastle.dart';

///
class KeyPair {
  ///
  KeyPair({
    required this.privateKey,
    required this.publicKey,
  });

  ///
  final RSAPrivateKey privateKey;

  ///
  final RSAPublicKey publicKey;
}

///
class BiometricResult {
  ///
  BiometricResult({
    required this.success,
    required this.attemptCount,
    this.signature,
    this.error,
  });

  ///
  final bool success;

  ///
  final String? signature;

  ///
  final String? error;

  ///
  final int attemptCount;
}

/// Configuration for SecureBiometrics
class SecureBiometricsConfig {
  /// Creates a new configuration instance
  const SecureBiometricsConfig({
    this.maxAttempts = 3,
    this.promptMessage = 'Please authenticate to sign transaction',
    this.keySize = 2048,
    this.biometricOnly = true,
  });

  /// Maximum number of failed authentication attempts allowed
  final int maxAttempts;

  /// Message shown to user during authentication
  final String promptMessage;

  /// RSA key size in bits (default 2048)
  final int keySize;

  /// Whether to only allow biometric authentication
  final bool biometricOnly;
}
