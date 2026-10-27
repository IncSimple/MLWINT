# Local model and dataset artifacts
This GitHub export intentionally omits trained artifacts. Nothing was deleted
from the original working project. `configs/artifacts.json` records relative paths,
sizes and SHA-256 hashes for inspected model files and the saved split. No hosted
download or model redistribution permission is assumed.

For inference, copy trusted artifacts from your original MLWINT project into the
same relative paths in this export:

```powershell
$original = 'D:\2) Study Material\Projects\MLWINT'
New-Item -ItemType Directory -Force .\src\models\candidates | Out-Null
Copy-Item -LiteralPath "$original\src\models\candidates\lightgbm_baseline.txt" -Destination .\src\models\candidates\
Copy-Item -LiteralPath "$original\src\models\candidates\xgboost_ember.json" -Destination .\src\models\candidates\
```

LightGBM requires the first file, XGBoost the second, ensemble both. Keep these
files ignored. Compare `Get-FileHash -Algorithm SHA256` with the manifest.
Research evaluation additionally needs sample arrays and the matching split;
obtain them from the same trusted experiment or regenerate in a separate copy
using the documented commands. No newly trained model will necessarily match
the recorded hash or score. Do not load untrusted joblib/pickle artifacts.
