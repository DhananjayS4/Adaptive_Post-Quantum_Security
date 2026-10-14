# Datasets

Raw datasets are intentionally not stored in this GitHub repository.

The local Edge-IIoTset corpus is approximately 10 GB and contains individual
files larger than GitHub's normal 100 MB object limit. The project reads the
dataset from a path configured in `config/system_config.yaml`.

Expected local file:

```text
../Edge-IIoTset Cyber Security Dataset of IoT & IIoT/
  Edge-IIoTset dataset/
    Selected dataset for ML and DL/
      ML-EdgeIIoT-dataset.csv
      DNN-EdgeIIoT-dataset.csv
```

VeReMi support is implemented, but its CSV is not currently available in the
workspace. Supply it explicitly:

```powershell
python -m adaptive_v2x_security.cli train `
  --dataset veremi `
  --path D:\data\Veremi_final_dataset.csv `
  --task binary
```

Edge-IIoTset licensing in the supplied dataset README grants academic use.
Commercial use requires permission from the dataset's lead author.
