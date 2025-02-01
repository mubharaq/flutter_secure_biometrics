import 'package:flutter_secure_storage/flutter_secure_storage.dart';

///
class StorageHelper {
  ///
  final storage = const FlutterSecureStorage();

  /// Stores data in secure storage.
  ///
  /// Takes a [key] and [data] as parameters.
  Future<void> storeData({required String key, required String data}) async {
    await storage.write(key: key, value: data);
  }

  /// Retrieves data from secure storage.
  ///
  /// Takes a [key] as a parameter and returns the associated data as a
  /// [String?]. If no data is found for the given [key], it returns null.
  Future<String?> retrieveData({required String key}) async {
    final data = await storage.read(key: key);
    return data;
  }

  /// Removes data from secure storage.
  ///
  /// Takes a [key] as a parameter and deletes the associated data from
  /// secure storage. If the [key] does not exist, no action is taken.
  Future<void> removeData({required String key}) async {
    await storage.delete(key: key);
  }
}
