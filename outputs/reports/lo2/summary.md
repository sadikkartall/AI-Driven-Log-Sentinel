# LO2 Rapor Ozeti (MVP)

## Feature reduction
- Total numeric cols (excluding timestamp): 23794
- Kept after NaN filter (<30%): 894
- Kept after variance filter: 367
- Selected TopK: 300

## Ablation summary

       mode      n     mean      std      p50      p90      p99  max
   log-only 213072 0.208094 0.152612 0.157040 0.395897 0.758104  1.0
metric-only  17200 0.244967 0.157058 0.204872 0.456291 0.806404  1.0