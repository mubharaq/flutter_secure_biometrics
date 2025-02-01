import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:secure_biometrics/secure_biometrics.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Biometrics Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const BiometricsDemo(),
    );
  }
}

class BiometricsDemo extends StatefulWidget {
  const BiometricsDemo({super.key});

  @override
  State<BiometricsDemo> createState() => _BiometricsDemoState();
}

class _BiometricsDemoState extends State<BiometricsDemo> {
  final SecureBiometrics _biometrics = SecureBiometrics.instance;
  String _status = 'Ready';
  String? _signature;
  String? _publicKeyPEM;
  bool _hasKeys = false;

  Future<void> _checkKeys() async {
    try {
      final publicKey = await _biometrics.getPublicKey();
      setState(() {
        _hasKeys = publicKey != null;
      });
    } catch (e) {
      _showError('Error checking keys', e);
    }
  }

  Future<void> _generateKeys() async {
    setState(() => _status = 'Generating keys...');
    try {
      final keyPair = await _biometrics.generateKeyPair();
      await _biometrics.storeKeyPair(
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      );
      await _checkKeys();
      setState(() => _status = 'Keys generated successfully');
    } catch (e) {
      _showError('Failed to generate keys', e);
    }
  }

  Future<void> _signMessage() async {
    setState(() => _status = 'Authenticating...');
    try {
      const message = 'Test message to sign';
      final signature = await _biometrics.signData(message);
      if (signature != null) {
        setState(() {
          _signature = base64.encode(signature);
          _status = 'Message signed successfully';
        });
      }
    } on MaxAttemptsExceededException {
      setState(() => _status = 'Too many failed attempts');
    } on BiometricNotAvailableException {
      setState(() => _status = 'Biometrics not available');
    } on BiometricAuthenticationException catch (e) {
      setState(() => _status = 'Authentication failed: ${e.message}');
    } catch (e) {
      _showError('Failed to sign message', e);
    }
  }

  Future<void> _verifySignature() async {
    if (_signature == null) {
      setState(() => _status = 'No signature to verify');
      return;
    }

    setState(() => _status = 'Verifying signature...');
    try {
      const message = 'Test message to sign';
      final isValid = await _biometrics.verifySignature(
        message,
        base64.decode(_signature!),
      );

      setState(() {
        _status = isValid ? 'Signature valid' : 'Signature invalid';
      });
    } catch (e) {
      _showError('Failed to verify signature', e);
    }
  }

  Future<void> _exportPublicKey() async {
    setState(() => _status = 'Exporting public key...');
    try {
      final pem = await _biometrics.exportPublicKeyPEM();
      setState(() {
        _publicKeyPEM = pem;
        _status = 'Public key exported';
      });
    } catch (e) {
      _showError('Failed to export public key', e);
    }
  }

  void _showError(String title, Object error) {
    setState(() => _status = '$title: $error');
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(error.toString()),
        backgroundColor: Colors.red,
      ),
    );
  }

  @override
  void initState() {
    super.initState();
    _checkKeys();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Secure Biometrics Demo'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Status: $_status',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Keys Present: ${_hasKeys ? "Yes" : "No"}',
                    style: Theme.of(context).textTheme.bodyLarge,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: _generateKeys,
            child: const Text('Generate Keys'),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _hasKeys ? _signMessage : null,
            child: const Text('Sign Message (Requires Biometric)'),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _signature != null ? _verifySignature : null,
            child: const Text('Verify Signature'),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: _hasKeys ? _exportPublicKey : null,
            child: const Text('Export Public Key'),
          ),
          if (_signature != null) ...[
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Signature:',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    SelectableText(_signature!),
                  ],
                ),
              ),
            ),
          ],
          if (_publicKeyPEM != null) ...[
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Public Key (PEM):',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    SelectableText(_publicKeyPEM!),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
