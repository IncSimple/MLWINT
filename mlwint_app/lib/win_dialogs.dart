// MLWINT Flutter window: the native Windows "Open" dialogs (files or a folder), through package:win32.
// Save as MLWINT/mlwint_app/lib/win_dialogs.dart
// Pure Dart (no Flutter plugin), so Windows Developer Mode is not needed to build the app.
import 'package:win32/win32.dart';

/// Shows the Windows dialog; returns the chosen paths ([] if cancelled). Only reads the names: nothing is opened.
List<String> pickPaths({bool folder = false, String title = ''}) {
  CoInitializeEx(COINIT(COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));
  final dialog = createInstance<IFileOpenDialog>(FileOpenDialog);
  final opts = dialog.getOptions() | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST |
      (folder ? FOS_PICKFOLDERS | FOS_ALLOWMULTISELECT : FOS_ALLOWMULTISELECT | FOS_FILEMUSTEXIST);
  dialog.setOptions(FILEOPENDIALOGOPTIONS(opts));
  if (title.isNotEmpty) {
    final t = title.toPcwstr();
    dialog.setTitle(t);
  }
  try {
    dialog.show(GetActiveWindow());
  } on WindowsException {
    return const []; // cancelled
  }
  final items = dialog.getResults();
  if (items == null) return const [];
  final out = <String>[];
  for (var i = 0; i < items.getCount(); i++) {
    final item = items.getItemAt(i);
    if (item == null) continue;
    final p = item.getDisplayName(SIGDN_FILESYSPATH);
    out.add(p.toDartString());
    CoTaskMemFree(p);
  }
  return out;
}