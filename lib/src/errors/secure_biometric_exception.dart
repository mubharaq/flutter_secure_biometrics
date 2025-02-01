/// Base exception class for secure biometrics
sealed class SecureBiometricException implements Exception {
  /// Creates a new [SecureBiometricException]
  const SecureBiometricException(this.message);

  /// The error message
  final String message;

  @override
  String toString() => 'SecureBiometricException: $message';
}

/// Thrown when biometric authentication fails
class BiometricAuthenticationException extends SecureBiometricException {
  /// Creates a new [BiometricAuthenticationException]
  const BiometricAuthenticationException(super.message);
}

/// Thrown when maximum authentication attempts are exceeded
class MaxAttemptsExceededException extends BiometricAuthenticationException {
  /// Creates a new [MaxAttemptsExceededException]
  const MaxAttemptsExceededException()
      : super('Maximum authentication attempts exceeded');
}

/// Thrown when biometric hardware is not available
class BiometricNotAvailableException extends BiometricAuthenticationException {
  /// Creates a new [BiometricNotAvailableException]
  const BiometricNotAvailableException()
      : super('Biometric authentication not available');
}

/// Thrown when key operations fail
class KeyOperationException extends SecureBiometricException {
  /// Creates a new [KeyOperationException]
  const KeyOperationException(super.message);
}

/// Thrown when key is not found in storage
class KeyNotFoundException extends KeyOperationException {
  /// Creates a new [KeyNotFoundException]
  const KeyNotFoundException(String keyType)
      : super('$keyType key not found in storage');
}

/// Thrown when PEM operations fail
class PEMException extends SecureBiometricException {
  /// Creates a new [PEMException]
  const PEMException(super.message);
}

/// Thrown when storage operations fail
class StorageException extends SecureBiometricException {
  /// Creates a new [StorageException]
  const StorageException(super.message);
}
