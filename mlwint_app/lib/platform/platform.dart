// MLWINT Flutter window: the few things that differ between the Windows app and the web demo.
// Save as MLWINT/mlwint_app/lib/platform/platform.dart
//   createEngine()  the Python engine on Windows (or the demo engine with --dart-define=MLWINT_DEMO=true);
//                   always the demo engine on the web
//   pickPaths()     the Windows "Open" dialog (sample paths in the demo)
//   openUrl()       an https link in the default browser / a new tab
//   appendErrorLog  window errors to MLWINT\reports\app-errors.txt (nothing on the web)
export 'native.dart' if (dart.library.js_interop) 'web.dart';
