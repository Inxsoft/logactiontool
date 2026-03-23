import 'dart:async';

import 'package:flutter/material.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'screens/dashboard_screen.dart';
import 'services/event_log_service.dart';

final _eventLogService = EventLogService();

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();

  const options = WindowOptions(
    size: Size(900, 620),
    minimumSize: Size(640, 480),
    center: true,
    title: 'LogActionTool',
    backgroundColor: Colors.transparent,
    skipTaskbar: false,
    titleBarStyle: TitleBarStyle.normal,
  );
  await windowManager.waitUntilReadyToShow(options, () async {
    await windowManager.show();
    await windowManager.focus();
  });

  runApp(const LogActionApp());

  // Hourly background collection (the first run happens in DashboardScreen.initState).
  Timer.periodic(const Duration(hours: 1), (_) {
    _eventLogService.collect();
  });
}

class LogActionApp extends StatefulWidget {
  const LogActionApp({super.key});

  @override
  State<LogActionApp> createState() => _LogActionAppState();
}

class _LogActionAppState extends State<LogActionApp>
    with TrayListener, WindowListener {
  @override
  void initState() {
    super.initState();
    trayManager.addListener(this);
    windowManager.addListener(this);
    _initTray();
  }

  @override
  void dispose() {
    trayManager.removeListener(this);
    windowManager.removeListener(this);
    super.dispose();
  }

  Future<void> _initTray() async {
    await trayManager.setIcon('assets/icon.ico');
    await trayManager.setToolTip('LogActionTool');
    await trayManager.setContextMenu(Menu(
      items: [
        MenuItem(key: 'show', label: 'Show'),
        MenuItem(key: 'run_now', label: 'Run Now'),
        MenuItem.separator(),
        MenuItem(key: 'exit', label: 'Exit'),
      ],
    ));
  }

  // ---------------------------------------------------------------------------
  // TrayListener
  // ---------------------------------------------------------------------------

  @override
  void onTrayIconMouseDown() {
    _showWindow();
  }

  @override
  void onTrayMenuItemClick(MenuItem item) {
    switch (item.key) {
      case 'show':
        _showWindow();
      case 'run_now':
        _eventLogService.collect();
      case 'exit':
        windowManager.destroy();
    }
  }

  // ---------------------------------------------------------------------------
  // WindowListener — intercept window close → hide to tray instead
  // ---------------------------------------------------------------------------

  @override
  void onWindowClose() async {
    await windowManager.hide();
  }

  void _showWindow() async {
    if (await windowManager.isMinimized()) await windowManager.restore();
    await windowManager.show();
    await windowManager.focus();
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'LogActionTool',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1A1D2E)),
        useMaterial3: true,
      ),
      home: DashboardScreen(eventLogService: _eventLogService),
    );
  }
}
