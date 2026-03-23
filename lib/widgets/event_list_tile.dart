import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../models/security_event.dart';

final _timeFmt = DateFormat('yyyy-MM-dd HH:mm:ss');

class EventListTile extends StatelessWidget {
  final SecurityEvent event;

  const EventListTile({super.key, required this.event});

  @override
  Widget build(BuildContext context) {
    final Color accent;
    final IconData icon;
    final String label;

    switch (event.eventId) {
      case 4625:
        accent = Colors.red.shade700;
        icon = Icons.lock_open;
        label = 'Failed Logon';
      case 4624:
        accent = Colors.green.shade700;
        icon = Icons.lock;
        label = 'Logon';
      case 4634:
        accent = Colors.blueGrey;
        icon = Icons.logout;
        label = 'Logoff';
      case 4648:
        accent = Colors.orange.shade700;
        icon = Icons.vpn_key;
        label = 'Explicit Logon';
      default:
        accent = Colors.grey;
        icon = Icons.info_outline;
        label = 'Event ${event.eventId}';
    }

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 3),
      decoration: BoxDecoration(
        color: accent.withValues(alpha: 0.07),
        border: Border(left: BorderSide(color: accent, width: 3)),
        borderRadius: const BorderRadius.only(
          topRight: Radius.circular(6),
          bottomRight: Radius.circular(6),
        ),
      ),
      child: ListTile(
        dense: true,
        leading: Icon(icon, color: accent, size: 20),
        title: Row(
          children: [
            Text(label,
                style: TextStyle(
                    fontWeight: FontWeight.w600,
                    color: accent,
                    fontSize: 13)),
            if (event.ipAddress != null) ...[
              const SizedBox(width: 8),
              Chip(
                label: Text(event.ipAddress!,
                    style: const TextStyle(fontSize: 11)),
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
                materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
            ],
            if (event.username != null) ...[
              const SizedBox(width: 4),
              Text(event.username!,
                  style: const TextStyle(fontSize: 12, color: Colors.black54)),
            ],
          ],
        ),
        subtitle: Text(
          _timeFmt.format(event.timeCreated),
          style: const TextStyle(fontSize: 11, color: Colors.black45),
        ),
        trailing: Text(
          '#${event.eventId}',
          style: const TextStyle(fontSize: 11, color: Colors.black38),
        ),
      ),
    );
  }
}
