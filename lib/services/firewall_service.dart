import 'dart:io';

/// Stub for firewall rule management — will be wired up in a future phase.
/// Uses `netsh advfirewall` under the hood (requires admin elevation).
class FirewallService {
  /// Block all inbound traffic from [ipAddress].
  Future<bool> blockIp(String ipAddress) async {
    final ruleName = 'LogActionTool_Block_$ipAddress';
    final result = await Process.run('netsh', [
      'advfirewall',
      'firewall',
      'add',
      'rule',
      'name=$ruleName',
      'dir=in',
      'action=block',
      'remoteip=$ipAddress',
      'enable=yes',
      'profile=any',
    ]);
    return result.exitCode == 0;
  }

  /// Remove a previously created block rule for [ipAddress].
  Future<bool> unblockIp(String ipAddress) async {
    final ruleName = 'LogActionTool_Block_$ipAddress';
    final result = await Process.run('netsh', [
      'advfirewall',
      'firewall',
      'delete',
      'rule',
      'name=$ruleName',
    ]);
    return result.exitCode == 0;
  }

  /// Returns all IPs currently blocked by LogActionTool rules.
  Future<List<String>> blockedIps() async {
    final result = await Process.run('netsh', [
      'advfirewall',
      'firewall',
      'show',
      'rule',
      'name=all',
    ]);
    final output = result.stdout as String;
    final blocked = <String>[];
    final ruleBlocks = output.split(RegExp(r'\r?\n\r?\n'));
    for (final block in ruleBlocks) {
      if (!block.contains('LogActionTool_Block_')) continue;
      final ipMatch = RegExp(r'RemoteIP:\s+(\S+)').firstMatch(block);
      if (ipMatch != null) blocked.add(ipMatch.group(1)!);
    }
    return blocked;
  }
}
