// Test file for hallucination detection
// Contains mix of real and fake Dart packages

// Real packages (should be legitimate) - verified in pub.dev
import 'package:http/http.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:dio/dio.dart';
import 'package:path/path.dart';

// Hallucinated packages (should be detected as fake)
import 'package:flutter_super_animations_xyz/animations.dart';
import 'package:dart_ai_helper_magic/helper.dart';
import 'package:magic_state_manager_pro/state.dart';
import 'package:ultra_http_client_plus/client.dart';
import 'package:awesome_flutter_utils_fake/utils.dart';

void main() {
  print('Testing hallucination detection');
}
