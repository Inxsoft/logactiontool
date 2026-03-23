import 'dart:io';

/// Windows Firewall rule management via `netsh advfirewall`.
/// Requires the app to run with administrator elevation.
class FirewallService {
  // Rule names cannot contain slashes, so we encode the CIDR by replacing
  // '/' with '_'. e.g. "45.227.254.0/24" → "LogActionTool_Block_45.227.254.0_24"
  static String _ruleName(String cidr) =>
      'LogActionTool_Block_${cidr.replaceAll('/', '_')}';

  /// Block all inbound traffic matching [cidr] (e.g. "1.2.3.4/32", "1.2.3.0/24").
  Future<bool> blockCidr(String cidr) async {
    final result = await Process.run('netsh', [
      'advfirewall', 'firewall', 'add', 'rule',
      'name=${_ruleName(cidr)}',
      'dir=in',
      'action=block',
      'remoteip=$cidr',
      'enable=yes',
      'profile=any',
    ]);
    return result.exitCode == 0;
  }

  /// Remove the block rule for [cidr].
  Future<bool> unblockCidr(String cidr) async {
    final result = await Process.run('netsh', [
      'advfirewall', 'firewall', 'delete', 'rule',
      'name=${_ruleName(cidr)}',
    ]);
    return result.exitCode == 0;
  }

  /// Returns all CIDRs currently blocked by LogActionTool firewall rules.
  Future<List<String>> blockedCidrs() async {
    final result = await Process.run(
      'netsh',
      ['advfirewall', 'firewall', 'show', 'rule', 'name=all'],
      stdoutEncoding: systemEncoding,
      stderrEncoding: systemEncoding,
    );
    final output = result.stdout as String;
    final blocked = <String>[];
    // netsh separates rules by blank lines
    for (final block in output.split(RegExp(r'\r?\n\r?\n'))) {
      if (!block.contains('LogActionTool_Block_')) continue;
      final m = RegExp(r'RemoteIP:\s+(\S+)').firstMatch(block);
      if (m != null) blocked.add(m.group(1)!);
    }
    return blocked;
  }
}
