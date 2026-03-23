import 'dart:convert';
import 'dart:io';

import '../models/security_event.dart';

const _dataDir = r'C:\ProgramData\LogActionTool';
const _logsDir = r'C:\ProgramData\LogActionTool\logs';
const _stateFile = r'C:\ProgramData\LogActionTool\last_run.json';

class EventLogService {
  /// Reads security events since the last run (or last 24 h on first run),
  /// persists them to a JSON file, and returns the parsed list.
  Future<List<SecurityEvent>> collect() async {
    final since = _loadLastRunTime();
    final events = await _queryEventLog(since);
    _saveLastRunTime(DateTime.now());
    _persistEvents(events);
    return events;
  }

  // ---------------------------------------------------------------------------
  // State helpers
  // ---------------------------------------------------------------------------

  DateTime _loadLastRunTime() {
    try {
      final f = File(_stateFile);
      if (f.existsSync()) {
        final map = jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
        return DateTime.parse(map['lastRun'] as String);
      }
    } catch (_) {}
    return DateTime.now().subtract(const Duration(hours: 24));
  }

  void _saveLastRunTime(DateTime time) {
    try {
      Directory(_dataDir).createSync(recursive: true);
      File(_stateFile).writeAsStringSync(
        jsonEncode({'lastRun': time.toIso8601String()}),
      );
    } catch (_) {}
  }

  // ---------------------------------------------------------------------------
  // PowerShell query
  // ---------------------------------------------------------------------------

  Future<List<SecurityEvent>> _queryEventLog(DateTime since) async {
    final sinceStr = since.toIso8601String();

    // Use a FilterHashtable with StartTime for efficiency; no MaxEvents limit.
    final script = r'''
param([string]$Since)
$since = [datetime]::Parse($Since)
try {
  $events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    StartTime = $since
    Id        = @(4624, 4625, 4634, 4648)
  } -ErrorAction SilentlyContinue
  if ($events) {
    $events | Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 2 -Compress
  } else {
    '[]'
  }
} catch {
  '[]'
}
''';

    final result = await Process.run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script, '-Since', sinceStr],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );

    final output = (result.stdout as String).trim();
    if (output.isEmpty || output == '[]') return [];

    try {
      final decoded = jsonDecode(output);
      final list = decoded is List ? decoded : [decoded];
      return list
          .whereType<Map<String, dynamic>>()
          .map(SecurityEvent.fromJson)
          .toList();
    } catch (e) {
      return [];
    }
  }

  // ---------------------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------------------

  void _persistEvents(List<SecurityEvent> events) {
    if (events.isEmpty) return;
    try {
      Directory(_logsDir).createSync(recursive: true);
      final now = DateTime.now();
      final fileName =
          '${now.year.toString().padLeft(4, '0')}-'
          '${now.month.toString().padLeft(2, '0')}-'
          '${now.day.toString().padLeft(2, '0')}_'
          '${now.hour.toString().padLeft(2, '0')}.json';
      final file = File('$_logsDir\\$fileName');
      file.writeAsStringSync(
        const JsonEncoder.withIndent('  ')
            .convert(events.map((e) => e.toJson()).toList()),
      );
    } catch (_) {}
  }
}
