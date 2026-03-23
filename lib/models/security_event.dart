class SecurityEvent {
  final String id;
  final DateTime timeCreated;
  final int eventId;
  final String message;
  final String? ipAddress;
  final String? username;

  SecurityEvent({
    required this.id,
    required this.timeCreated,
    required this.eventId,
    required this.message,
    this.ipAddress,
    this.username,
  });

  bool get isFailedLogon => eventId == 4625;
  bool get isSuccessLogon => eventId == 4624;

  factory SecurityEvent.fromJson(Map<String, dynamic> json) {
    final message = json['Message'] as String? ?? '';
    return SecurityEvent(
      id: '${json['TimeCreated']}_${json['Id']}',
      timeCreated: _parseDate(json['TimeCreated']),
      eventId: (json['Id'] as num).toInt(),
      message: message,
      ipAddress: _extractIpAddress(message),
      username: _extractUsername(message),
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'timeCreated': timeCreated.toIso8601String(),
        'eventId': eventId,
        'message': message,
        'ipAddress': ipAddress,
        'username': username,
      };

  static DateTime _parseDate(dynamic value) {
    if (value == null) return DateTime.now();
    final s = value.toString();
    // PowerShell date format: "/Date(milliseconds)/" or ISO string
    final msMatch = RegExp(r'/Date\((\d+)\)/').firstMatch(s);
    if (msMatch != null) {
      return DateTime.fromMillisecondsSinceEpoch(int.parse(msMatch.group(1)!));
    }
    return DateTime.tryParse(s) ?? DateTime.now();
  }

  static String? _extractIpAddress(String message) {
    final match = RegExp(
      r'Source Network Address:\s+([\d\.]+|[\da-fA-F:]+)',
    ).firstMatch(message);
    final ip = match?.group(1);
    if (ip == null || ip == '-' || ip == '::1' || ip == '127.0.0.1') {
      return null;
    }
    return ip;
  }

  static String? _extractUsername(String message) {
    final match = RegExp(
      r'Account Name:\s+(\S+)',
    ).firstMatch(message);
    final name = match?.group(1);
    if (name == null || name == '-') return null;
    return name;
  }
}
