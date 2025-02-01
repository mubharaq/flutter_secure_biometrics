/// Storage keys used by SecureBiometrics
class StorageKeys {
  const StorageKeys._();

  /// Key for storing failed biometric attempts
  static const String attempts = '_f_att_key';

  /// Key for storing generated private signature key
  static const String privateKey = '_sig_key';

  /// Key for storing generated public signature key
  static const String publicKey = '_public_sig_key';
}

/// Cryptographic constants used by SecureBiometrics
class Constants {
  const Constants._();

  /// Maximum allowed consecutive failed biometric attempts
  static const int maxAttempts = 3;

  /// Default RSA key size in bits
  static const int defaultKeySize = 2048;

  /// RSA public exponent
  static const String publicExponent = '65537';

  /// Parameter used for random number generation
  static const String randomParameter = 'AES/CTR/PRNG';

  /// RSA padding scheme
  static const String padding = '0609608648016503040201';
}
