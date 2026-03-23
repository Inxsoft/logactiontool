import 'dart:async';

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../models/security_event.dart';
import '../services/event_log_service.dart';
import '../services/firewall_service.dart';

final _timeFmt = DateFormat('HH:mm:ss');

class DashboardScreen extends StatefulWidget {
  final EventLogService eventLogService;

  const DashboardScreen({super.key, required this.eventLogService});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final _firewallService = FirewallService();

  List<SecurityEvent> _events = [];
  int _bannedCount = 0;
  bool _loading = false;
  String _status = 'Idle';
  DateTime? _lastRun;
  DateTime? _nextRun;
  Timer? _countdownTimer;

  @override
  void initState() {
    super.initState();
    _runCollection();
    _refreshBannedCount();
    _countdownTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) => setState(() {}),
    );
  }

  @override
  void dispose() {
    _countdownTimer?.cancel();
    super.dispose();
  }

  Future<void> _refreshBannedCount() async {
    final cidrs = await _firewallService.blockedCidrs();
    if (mounted) setState(() => _bannedCount = cidrs.length);
  }

  Future<void> _runCollection() async {
    if (_loading) return;
    setState(() {
      _loading = true;
      _status = 'Reading security logs…';
    });
    try {
      final events = await widget.eventLogService.collect();
      final now = DateTime.now();
      setState(() {
        _events = events;
        _lastRun = now;
        _nextRun = now.add(const Duration(hours: 1));
        _status = 'Collected ${events.length} event(s)';
      });
    } catch (e) {
      setState(() => _status = 'Error: $e');
    } finally {
      setState(() => _loading = false);
    }
  }

  String _countdown() {
    if (_nextRun == null) return '';
    final diff = _nextRun!.difference(DateTime.now());
    if (diff.isNegative) return 'due now';
    final h = diff.inHours.toString().padLeft(2, '0');
    final m = (diff.inMinutes % 60).toString().padLeft(2, '0');
    final s = (diff.inSeconds % 60).toString().padLeft(2, '0');
    return 'Next run in $h:$m:$s';
  }

  // ---------------------------------------------------------------------------
  // Derived stats
  // ---------------------------------------------------------------------------

  int get _failedCount => _events.where((e) => e.isFailedLogon).length;
  int get _successCount => _events.where((e) => e.isSuccessLogon).length;
  Set<String> get _uniqueIps =>
      _events.map((e) => e.ipAddress).whereType<String>().toSet();

  /// Failed-login attempt count per IP, sorted descending.
  Map<String, int> get _ipFailedCounts {
    final counts = <String, int>{};
    for (final e in _events) {
      if (e.isFailedLogon && e.ipAddress != null) {
        counts[e.ipAddress!] = (counts[e.ipAddress!] ?? 0) + 1;
      }
    }
    final sorted = counts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    return Map.fromEntries(sorted);
  }

  // ---------------------------------------------------------------------------
  // CIDR helpers
  // ---------------------------------------------------------------------------

  static String _cidr32(String ip) => '$ip/32';

  static String _cidr24(String ip) {
    final p = ip.split('.');
    if (p.length < 4) return '$ip/24';
    return '${p[0]}.${p[1]}.${p[2]}.0/24';
  }

  static String _cidr16(String ip) {
    final p = ip.split('.');
    if (p.length < 4) return '$ip/16';
    return '${p[0]}.${p[1]}.0.0/16';
  }

  // ---------------------------------------------------------------------------
  // Dialogs
  // ---------------------------------------------------------------------------

  Future<void> _confirmAndBan(String ip, String cidr) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: Row(
          children: [
            const Icon(Icons.block, color: Colors.red, size: 20),
            const SizedBox(width: 8),
            const Text('Confirm Ban'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Source IP: $ip'),
            const SizedBox(height: 8),
            Text(
              cidr,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'This will create an inbound block rule in Windows Firewall for $cidr.',
              style: const TextStyle(color: Colors.black54, fontSize: 13),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton.icon(
            icon: const Icon(Icons.block, size: 16),
            label: const Text('Ban'),
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(context, true),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    final ok = await _firewallService.blockCidr(cidr);
    await _refreshBannedCount();

    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(ok ? 'Banned $cidr' : 'Failed to ban $cidr — check admin rights'),
        backgroundColor: ok ? Colors.green.shade700 : Colors.red.shade700,
        duration: const Duration(seconds: 3),
      ),
    );
  }

  void _showUniqueIpsDialog() async {
    final counts = _ipFailedCounts;

    // Load current banned CIDRs first so we can mark already-banned IPs.
    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AlertDialog(
        content: Row(children: [
          CircularProgressIndicator(),
          SizedBox(width: 16),
          Text('Loading…'),
        ]),
      ),
    );
    final initialBanned = await _firewallService.blockedCidrs();
    if (!mounted) return;
    Navigator.pop(context);

    showDialog<void>(
      context: context,
      builder: (outerCtx) {
        // Mutable set — lives in the outer builder closure, survives
        // StatefulBuilder rebuilds.
        var banned = initialBanned.toSet();

        Future<void> doBan(String ip, String cidr, void Function(void Function()) setDialogState) async {
          final confirmed = await showDialog<bool>(
            context: context,
            builder: (_) => AlertDialog(
              title: Row(children: [
                const Icon(Icons.block, color: Colors.red, size: 20),
                const SizedBox(width: 8),
                const Text('Confirm Ban'),
              ]),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Source IP: $ip'),
                  const SizedBox(height: 8),
                  Text(cidr,
                      style: const TextStyle(
                          fontFamily: 'monospace',
                          fontWeight: FontWeight.bold,
                          fontSize: 16)),
                  const SizedBox(height: 12),
                  Text(
                    'This will create an inbound block rule in Windows Firewall for $cidr.',
                    style: const TextStyle(color: Colors.black54, fontSize: 13),
                  ),
                ],
              ),
              actions: [
                TextButton(
                    onPressed: () => Navigator.pop(context, false),
                    child: const Text('Cancel')),
                FilledButton.icon(
                  icon: const Icon(Icons.block, size: 16),
                  label: const Text('Ban'),
                  style: FilledButton.styleFrom(backgroundColor: Colors.red),
                  onPressed: () => Navigator.pop(context, true),
                ),
              ],
            ),
          );
          if (confirmed != true || !mounted) return;

          final ok = await _firewallService.blockCidr(cidr);
          if (ok) {
            setDialogState(() => banned.add(cidr));
            await _refreshBannedCount();
          }
          if (!mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
            content: Text(ok ? 'Banned $cidr' : 'Failed to ban $cidr — check admin rights'),
            backgroundColor: ok ? Colors.green.shade700 : Colors.red.shade700,
            duration: const Duration(seconds: 3),
          ));
        }

        return StatefulBuilder(builder: (ctx, setDialogState) {
          return Dialog(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 600, maxHeight: 540),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Header
                  Container(
                    decoration: const BoxDecoration(
                      color: Color(0xFF1A1D2E),
                      borderRadius:
                          BorderRadius.vertical(top: Radius.circular(12)),
                    ),
                    padding: const EdgeInsets.symmetric(
                        horizontal: 20, vertical: 14),
                    child: Row(children: [
                      const Icon(Icons.language, color: Colors.blue, size: 20),
                      const SizedBox(width: 8),
                      Text('Unique IPs  (${counts.length})',
                          style: const TextStyle(
                              color: Colors.white,
                              fontWeight: FontWeight.bold,
                              fontSize: 15)),
                      const Spacer(),
                      const Text('Failed attempts',
                          style: TextStyle(
                              color: Colors.white38, fontSize: 12)),
                    ]),
                  ),
                  // List
                  Flexible(
                    child: counts.isEmpty
                        ? const Padding(
                            padding: EdgeInsets.all(24),
                            child: Text('No IPs recorded yet.'),
                          )
                        : ListView.separated(
                            shrinkWrap: true,
                            itemCount: counts.length,
                            separatorBuilder: (_, x) =>
                                const Divider(height: 1, indent: 16),
                            itemBuilder: (_, i) {
                              final ip = counts.keys.elementAt(i);
                              final attempts = counts.values.elementAt(i);
                              final cidr32 = _cidr32(ip);
                              final cidr24 = _cidr24(ip);
                              final cidr16 = _cidr16(ip);
                              final banned32 = banned.contains(cidr32);
                              final banned24 = banned.contains(cidr24);
                              final banned16 = banned.contains(cidr16);
                              final anyBanned = banned32 || banned24 || banned16;

                              return Container(
                                color: anyBanned
                                    ? Colors.green.shade50
                                    : null,
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 12, vertical: 7),
                                child: Row(children: [
                                  // IP + attempt count + ban badges
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Row(children: [
                                          Text(ip,
                                              style: const TextStyle(
                                                fontFamily: 'monospace',
                                                fontWeight: FontWeight.w600,
                                                fontSize: 13,
                                              )),
                                          const SizedBox(width: 8),
                                          // Attempt count badge
                                          Container(
                                            padding: const EdgeInsets.symmetric(
                                                horizontal: 6, vertical: 1),
                                            decoration: BoxDecoration(
                                              color: Colors.red.shade50,
                                              border: Border.all(
                                                  color: Colors.red.shade200),
                                              borderRadius:
                                                  BorderRadius.circular(10),
                                            ),
                                            child: Text('$attempts',
                                                style: TextStyle(
                                                    color: Colors.red.shade700,
                                                    fontSize: 11,
                                                    fontWeight:
                                                        FontWeight.bold)),
                                          ),
                                        ]),
                                        // Ban coverage badges
                                        if (anyBanned) ...[
                                          const SizedBox(height: 3),
                                          Wrap(spacing: 4, children: [
                                            if (banned32)
                                              _bannedBadge('IP'),
                                            if (banned24)
                                              _bannedBadge('/24'),
                                            if (banned16)
                                              _bannedBadge('/16'),
                                          ]),
                                        ],
                                      ],
                                    ),
                                  ),
                                  // Ban buttons
                                  _ipBanButton('Ban IP', Colors.red.shade700,
                                      banned32, cidr32,
                                      () => doBan(ip, cidr32, setDialogState)),
                                  const SizedBox(width: 4),
                                  _ipBanButton('Ban /24',
                                      Colors.orange.shade700, banned24, cidr24,
                                      () => doBan(ip, cidr24, setDialogState)),
                                  const SizedBox(width: 4),
                                  _ipBanButton('Ban /16',
                                      Colors.deepOrange.shade700, banned16,
                                      cidr16,
                                      () => doBan(ip, cidr16, setDialogState)),
                                ]),
                              );
                            },
                          ),
                  ),
                  // Footer
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                    child: Align(
                      alignment: Alignment.centerRight,
                      child: TextButton(
                        onPressed: () => Navigator.pop(outerCtx),
                        child: const Text('Close'),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          );
        });
      },
    );
  }

  Widget _bannedBadge(String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
      decoration: BoxDecoration(
        color: Colors.green.shade700,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        const Icon(Icons.check, color: Colors.white, size: 10),
        const SizedBox(width: 2),
        Text('Banned $label',
            style: const TextStyle(
                color: Colors.white,
                fontSize: 10,
                fontWeight: FontWeight.w600)),
      ]),
    );
  }

  /// Ban button that shows "✓ Banned" when [isBanned] is true.
  Widget _ipBanButton(
      String label, Color color, bool isBanned, String cidr, VoidCallback onTap) {
    if (isBanned) {
      return SizedBox(
        height: 28,
        child: Tooltip(
          message: cidr,
          child: FilledButton.icon(
            icon: const Icon(Icons.check, size: 12),
            label: Text(label.replaceFirst('Ban ', '')),
            style: FilledButton.styleFrom(
              backgroundColor: Colors.green.shade700,
              padding: const EdgeInsets.symmetric(horizontal: 8),
              minimumSize: const Size(0, 28),
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              textStyle:
                  const TextStyle(fontSize: 11, fontWeight: FontWeight.w600),
            ),
            onPressed: null, // already banned — disable
          ),
        ),
      );
    }
    return _banButton(label, color, onTap);
  }

  void _showBannedDialog() async {
    // Show loading spinner while fetching rules
    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AlertDialog(
        content: Row(children: [
          CircularProgressIndicator(),
          SizedBox(width: 16),
          Text('Loading firewall rules…'),
        ]),
      ),
    );

    final initial = await _firewallService.blockedCidrs();
    if (!mounted) return;
    Navigator.pop(context);

    showDialog<void>(
      context: context,
      builder: (outerCtx) => StatefulBuilder(
        builder: (ctx, setDialogState) {
          var banned = initial; // local mutable copy for this dialog

          Future<void> doUnban(String cidr) async {
            final ok = await _firewallService.unblockCidr(cidr);
            final updated = await _firewallService.blockedCidrs();
            setDialogState(() => banned = updated);
            await _refreshBannedCount();
            if (!mounted) return;
            ScaffoldMessenger.of(context).showSnackBar(SnackBar(
              content: Text(ok ? 'Unbanned $cidr' : 'Failed to unban $cidr'),
              backgroundColor:
                  ok ? Colors.green.shade700 : Colors.red.shade700,
              duration: const Duration(seconds: 3),
            ));
          }

          return Dialog(
            child: ConstrainedBox(
              constraints:
                  const BoxConstraints(maxWidth: 480, maxHeight: 460),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Header
                  Container(
                    decoration: const BoxDecoration(
                      color: Color(0xFF1A1D2E),
                      borderRadius:
                          BorderRadius.vertical(top: Radius.circular(12)),
                    ),
                    padding: const EdgeInsets.symmetric(
                        horizontal: 20, vertical: 14),
                    child: Row(children: [
                      const Icon(Icons.block, color: Colors.red, size: 20),
                      const SizedBox(width: 8),
                      Text(
                        'Currently Banned  (${banned.length})',
                        style: const TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 15),
                      ),
                    ]),
                  ),
                  // List
                  Flexible(
                    child: banned.isEmpty
                        ? const Padding(
                            padding: EdgeInsets.all(24),
                            child: Text(
                                'No IPs are currently banned by LogActionTool.'),
                          )
                        : ListView.separated(
                            shrinkWrap: true,
                            itemCount: banned.length,
                            separatorBuilder: (_, x) =>
                                const Divider(height: 1, indent: 16),
                            itemBuilder: (_, i) {
                              final cidr = banned[i];
                              return ListTile(
                                dense: true,
                                leading: const Icon(Icons.block,
                                    color: Colors.red, size: 18),
                                title: Text(
                                  cidr,
                                  style: const TextStyle(
                                      fontFamily: 'monospace',
                                      fontWeight: FontWeight.w600),
                                ),
                                trailing: OutlinedButton.icon(
                                  icon: const Icon(Icons.lock_open, size: 14),
                                  label: const Text('Unban'),
                                  style: OutlinedButton.styleFrom(
                                    foregroundColor: Colors.orange.shade700,
                                    side: BorderSide(
                                        color: Colors.orange.shade300),
                                    padding: const EdgeInsets.symmetric(
                                        horizontal: 10),
                                    minimumSize: const Size(0, 28),
                                    tapTargetSize:
                                        MaterialTapTargetSize.shrinkWrap,
                                    textStyle: const TextStyle(
                                        fontSize: 11,
                                        fontWeight: FontWeight.w600),
                                  ),
                                  onPressed: () => doUnban(cidr),
                                ),
                              );
                            },
                          ),
                  ),
                  // Footer
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                    child: Align(
                      alignment: Alignment.centerRight,
                      child: TextButton(
                        onPressed: () => Navigator.pop(outerCtx),
                        child: const Text('Close'),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _banButton(String label, Color color, VoidCallback onTap) {
    return OutlinedButton(
      onPressed: onTap,
      style: OutlinedButton.styleFrom(
        foregroundColor: color,
        side: BorderSide(color: color.withValues(alpha: 0.6)),
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 0),
        minimumSize: const Size(0, 28),
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        textStyle: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600),
      ),
      child: Text(label),
    );
  }

  // ---------------------------------------------------------------------------
  // UI
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF5F6FA),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1A1D2E),
        foregroundColor: Colors.white,
        title: const Text('LogActionTool',
            style: TextStyle(fontWeight: FontWeight.bold)),
        actions: [
          if (_loading)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16),
              child: Center(
                child: SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: Colors.white),
                ),
              ),
            )
          else
            IconButton(
              icon: const Icon(Icons.refresh),
              tooltip: 'Run now',
              onPressed: _runCollection,
            ),
        ],
      ),
      body: Column(
        children: [
          _buildSummaryBar(),
          _buildStatusBar(),
          const Divider(height: 1),
          Expanded(child: _buildContent()),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Content area
  // ---------------------------------------------------------------------------

  Widget _buildContent() {
    if (_events.isEmpty && !_loading) {
      return const Center(child: Text('No events yet. Press refresh to collect.'));
    }
    if (_loading && _events.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildTopOffenderCard(),
          const SizedBox(height: 12),
          _buildLastEventCard(),
          const SizedBox(height: 12),
          _buildTop10Card(),
        ],
      ),
    );
  }

  static const _cardDecoration = BoxDecoration(
    color: Colors.white,
    borderRadius: BorderRadius.all(Radius.circular(8)),
    boxShadow: [BoxShadow(color: Color(0x0F000000), blurRadius: 4, offset: Offset(0, 2))],
  );

  Widget _buildTopOffenderCard() {
    final counts = _ipFailedCounts;
    if (counts.isEmpty) {
      return Container(
        decoration: _cardDecoration,
        padding: const EdgeInsets.all(16),
        child: const Text('No failed logon events.'),
      );
    }
    final topIp = counts.keys.first;
    final topCount = counts.values.first;

    return Container(
      decoration: _cardDecoration,
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: Colors.red.shade50,
              shape: BoxShape.circle,
            ),
            child: Icon(Icons.warning_amber_rounded,
                color: Colors.red.shade700, size: 28),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('TOP OFFENDER',
                    style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.2,
                        color: Colors.black38)),
                const SizedBox(height: 2),
                Text(topIp,
                    style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 20,
                        fontWeight: FontWeight.bold)),
                Text('$topCount failed attempt${topCount == 1 ? '' : 's'}',
                    style: TextStyle(color: Colors.red.shade700, fontSize: 13)),
              ],
            ),
          ),
          // Quick ban buttons
          _banButton('Ban IP', Colors.red.shade700,
              () => _confirmAndBan(topIp, _cidr32(topIp))),
          const SizedBox(width: 6),
          _banButton('Ban /24', Colors.orange.shade700,
              () => _confirmAndBan(topIp, _cidr24(topIp))),
        ],
      ),
    );
  }

  Widget _buildLastEventCard() {
    if (_events.isEmpty) return const SizedBox.shrink();
    final e = _events.first;

    final Color accent;
    final IconData icon;
    final String label;
    switch (e.eventId) {
      case 4625:
        accent = Colors.red.shade700; icon = Icons.lock_open; label = 'Failed Logon';
      case 4624:
        accent = Colors.green.shade700; icon = Icons.lock; label = 'Logon';
      case 4634:
        accent = Colors.blueGrey; icon = Icons.logout; label = 'Logoff';
      case 4648:
        accent = Colors.orange.shade700; icon = Icons.vpn_key; label = 'Explicit Logon';
      default:
        accent = Colors.grey; icon = Icons.info_outline; label = 'Event ${e.eventId}';
    }

    return Container(
      decoration: _cardDecoration,
      padding: const EdgeInsets.all(16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: accent.withValues(alpha: 0.08),
              shape: BoxShape.circle,
            ),
            child: Icon(icon, color: accent, size: 26),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('LAST EVENT',
                    style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.2,
                        color: Colors.black38)),
                const SizedBox(height: 2),
                Row(children: [
                  Text(label,
                      style: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: accent,
                          fontSize: 15)),
                  const SizedBox(width: 8),
                  Text(_timeFmt.format(e.timeCreated),
                      style:
                          const TextStyle(color: Colors.black45, fontSize: 12)),
                ]),
                const SizedBox(height: 4),
                Wrap(spacing: 12, children: [
                  if (e.ipAddress != null)
                    _detailChip(Icons.language, e.ipAddress!),
                  if (e.username != null)
                    _detailChip(Icons.person_outline, e.username!),
                ]),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTop10Card() {
    final counts = _ipFailedCounts;
    if (counts.isEmpty) return const SizedBox.shrink();
    final top10 = counts.entries.take(10).toList();

    return Container(
      decoration: _cardDecoration,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 14, 16, 8),
            child: Row(children: [
              const Text('TOP 10 OFFENDERS',
                  style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.2,
                      color: Colors.black38)),
              const Spacer(),
              const Text('ATTEMPTS',
                  style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.2,
                      color: Colors.black38)),
            ]),
          ),
          const Divider(height: 1),
          ...top10.asMap().entries.map((entry) {
            final rank = entry.key + 1;
            final ip = entry.value.key;
            final count = entry.value.value;
            final maxCount = top10.first.value;
            final fraction = maxCount > 0 ? count / maxCount : 0.0;

            return Column(children: [
              Padding(
                padding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: Row(children: [
                  SizedBox(
                    width: 22,
                    child: Text('$rank',
                        style: TextStyle(
                            color: rank == 1
                                ? Colors.red.shade700
                                : Colors.black38,
                            fontWeight: rank == 1
                                ? FontWeight.bold
                                : FontWeight.normal,
                            fontSize: 13)),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(ip,
                            style: const TextStyle(
                                fontFamily: 'monospace',
                                fontWeight: FontWeight.w600,
                                fontSize: 13)),
                        const SizedBox(height: 3),
                        ClipRRect(
                          borderRadius: BorderRadius.circular(2),
                          child: LinearProgressIndicator(
                            value: fraction,
                            minHeight: 4,
                            backgroundColor: Colors.grey.shade100,
                            valueColor: AlwaysStoppedAnimation<Color>(
                                rank == 1
                                    ? Colors.red.shade600
                                    : Colors.orange.shade400),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 16),
                  Text('$count',
                      style: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: rank == 1
                              ? Colors.red.shade700
                              : Colors.black87,
                          fontSize: 14)),
                ]),
              ),
              if (rank < top10.length) const Divider(height: 1, indent: 46),
            ]);
          }),
          const SizedBox(height: 4),
        ],
      ),
    );
  }

  Widget _detailChip(IconData icon, String label) {
    return Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, size: 13, color: Colors.black45),
      const SizedBox(width: 3),
      Text(label,
          style: const TextStyle(fontSize: 12, color: Colors.black54)),
    ]);
  }

  Widget _buildSummaryBar() {
    return Container(
      color: const Color(0xFF1A1D2E),
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
      child: Row(
        children: [
          _statChip(Icons.list_alt, '${_events.length}', 'Events',
              Colors.white70, null),
          const SizedBox(width: 12),
          _statChip(Icons.lock_open, '$_failedCount', 'Failed',
              Colors.red.shade300, null),
          const SizedBox(width: 12),
          _statChip(Icons.lock, '$_successCount', 'Success',
              Colors.green.shade300, null),
          const SizedBox(width: 12),
          _statChip(Icons.language, '${_uniqueIps.length}', 'Unique IPs',
              Colors.blue.shade300, _showUniqueIpsDialog),
          const SizedBox(width: 12),
          _statChip(Icons.block, '$_bannedCount', 'Banned',
              Colors.red.shade300, _showBannedDialog),
        ],
      ),
    );
  }

  Widget _statChip(
    IconData icon,
    String value,
    String label,
    Color color,
    VoidCallback? onTap,
  ) {
    final content = Row(
      children: [
        Icon(icon, color: color, size: 16),
        const SizedBox(width: 4),
        RichText(
          text: TextSpan(children: [
            TextSpan(
                text: value,
                style: TextStyle(
                    color: color,
                    fontWeight: FontWeight.bold,
                    fontSize: 14)),
            TextSpan(
                text: ' $label',
                style: const TextStyle(color: Colors.white38, fontSize: 12)),
          ]),
        ),
        if (onTap != null) ...[
          const SizedBox(width: 3),
          Icon(Icons.keyboard_arrow_down,
              color: color.withValues(alpha: 0.6), size: 14),
        ],
      ],
    );

    if (onTap == null) return content;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(6),
      hoverColor: Colors.white.withValues(alpha: 0.08),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
        child: content,
      ),
    );
  }

  Widget _buildStatusBar() {
    return Container(
      color: const Color(0xFF23263A),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: Row(
        children: [
          Text(_status,
              style: const TextStyle(color: Colors.white60, fontSize: 12)),
          const Spacer(),
          if (_lastRun != null)
            Text('Last: ${_timeFmt.format(_lastRun!)}  ',
                style: const TextStyle(color: Colors.white38, fontSize: 12)),
          Text(_countdown(),
              style: const TextStyle(color: Colors.white38, fontSize: 12)),
        ],
      ),
    );
  }
}
