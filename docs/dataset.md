# Dataset provenance
Source: [Elastic EMBER](https://github.com/elastic/ember), 2018 release, feature v2.
The upstream README links `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2`.
Its published SHA-256 is
`b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`.
Verify your downloaded archive before extraction:

```powershell
Get-FileHash .\downloads\ember_dataset_2018_2.tar.bz2 -Algorithm SHA256
```

The local archive was not rehashed during setup. Place `train_features_0.jsonl`
through `train_features_5.jsonl` and `test_features.jsonl` in `data/raw/ember2018`.
The inspected chunk manifest reports 600,000 labeled rows, 200,000 skipped rows,
1,203 chunks and all six training files completed. Labels: 0 benign, 1 malicious,
-1 unlabeled. Preparation samples 100,000 rows (50,000 per class), seed 42.
The sample indices refer to this exact sample row ordering. A regenerated sample
is comparable only if inputs, ordering, code and random generator match.

[Upstream license](https://github.com/elastic/ember/blob/master/LICENSE.txt):
extractor code AGPLv3, downloadable data MIT. Preserve applicable notices and
review dependencies before distributing derived artifacts. The MLWINT MIT license
does not grant additional rights over third-party content. Dataset and model
redistribution are deliberately deferred; only source, reports and split indices
are included here. No raw executable samples are copied.
