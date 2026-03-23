import 'dart:async';

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../models/security_event.dart';
import '../services/event_log_service.dart';
import '../widgets/event_list_tile.dart';

final _timeFmt = DateFormat('HH:mm:ss');

class DashboardScreen extends StatefulWidget {
  final EventLogService eventLogService;

  const DashboardScreen({super.key, required this.eventLogService});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  List<SecurityEvent> _events = [];
  bool _loading = false;
  String _status = 'Idle';
  DateTime? _lastRun;
  DateTime? _nextRun;
  Timer? _countdownTimer;

  @override
  void initState() {
    super.initState();
    _runCollection();
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
          Expanded(
            child: _events.isEmpty && !_loading
                ? const Center(
                    child: Text('No events yet. Press refresh to collect.'))
                : ListView.builder(
                    itemCount: _events.length,
                    itemBuilder: (_, i) => EventListTile(event: _events[i]),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildSummaryBar() {
    return Container(
      color: const Color(0xFF1A1D2E),
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
      child: Row(
        children: [
          _statChip(Icons.list_alt, '${_events.length}', 'Events',
              Colors.white70),
          const SizedBox(width: 12),
          _statChip(Icons.lock_open, '$_failedCount', 'Failed',
              Colors.red.shade300),
          const SizedBox(width: 12),
          _statChip(Icons.lock, '$_successCount', 'Success',
              Colors.green.shade300),
          const SizedBox(width: 12),
          _statChip(Icons.language, '${_uniqueIps.length}', 'Unique IPs',
              Colors.blue.shade300),
        ],
      ),
    );
  }

  Widget _statChip(IconData icon, String value, String label, Color color) {
    return Row(
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
      ],
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
