## 🪐PlanetServe

[![Artifacts Available](https://img.shields.io/badge/Artifacts-Available-%23F39C12)](https://secartifacts.github.io/usenixsec2025/badges)
[![Artifacts Functional](https://img.shields.io/badge/Artifacts-Functional-%233498DB)](https://secartifacts.github.io/usenixsec2025/badges)
[![Artifacts Reproduced](https://img.shields.io/badge/Artifacts-Reproduced-%239B59B6)](https://secartifacts.github.io/usenixsec2025/badges)

📄 **Paper:** [PlanetServe](https://www.usenix.org/system/files/nsdi26-fang.pdf)

Welcome to **PlanetServe**, an open LLM serving overlay that harnesses computing resources from decentralized contributors.

## 📃 Overview


<img src="docs/PlanetServe.png" width="85%">


```
.
├── build/                   # Build files
├── CMakeLists.txt           # CMake configuration
├── configs/                 # Configuration files for local testing
├── demo/                    # Hard-coded local demo examples
├── deps/                    # Third-party dependencies
├── docs/                    # figures, and demo GIFs
├── eval/                    # Reproduction and evaluation instructions
│   ├── hrt+lb/              # Hash Radix Tree + load-balancing experiments
│   ├── malicious_frac/      # Malicious fraction simulation
│   ├── prep_decry_lat/      # Prepare/decrypt latency measurements
│   ├── verification/        # Verification prototype
│   └── workload/            # Workload driver & monitor
├── models/                  # Model files (e.g., .gguf)
├── planetllm_tendermint/    # Tendermint-based consensus demo for verification committee
├── README.md                # Project overview
├── scripts/                 # Scripts to run local demos
├── src/                     # Core demo system implementation
└── tests/                   # tests
```

## 📚 Repository Overview

This repository is organized into several modules.  
Each directory includes its own `README.md` with detailed documentation.

### Demo

- **[`demo/`](demo/README.md)**  
  Local demos that showcase the PlanetServe system design by running multiple logical nodes on a single machine, without requiring GPU.

### Evaluation

- **eval/**  
  Scripts and configurations for evaluation.

  - **[`hrt+lb/`](eval/hrt+lb/README.md)**  
    Experiments on Hash Radix Tree + load-balancing and Confidemtial Computing.

  - **[`malicious_frac/`](eval/malicious_frac/README.md)**  
    Simulation of anonimity and confidentiality under different fractions of malicious nodes.

  - **[`prep_decry_lat/`](eval/prep_decry_lat/README.md)**  
    Microbenchmarks measuring preparation and decryption latency.

  - **[`verification/`](eval/verification/README.md)**  
    Prototype for verification logic.

  - **[`workload/`](eval/workload/README.md)**  
    Prototype for scheduling and load balancing logic.

## Citation

If you use PlanetServe in your research, please cite our paper:

```bibtex
@inproceedings {316600,
author = {Fei Fang and Yifan Hua and Shengze Wang and Ruilin Zhou and Yi Liu and Chen Qian and Xiaoxue Zhang},
title = {{PlanetServe}: A Decentralized, Scalable, and {Privacy-Preserving} Overlay for Democratizing Large Language Model Serving},
booktitle = {23rd USENIX Symposium on Networked Systems Design and Implementation (NSDI 26)},
year = {2026},
isbn = {978-1-939133-54-0},
address = {Renton, WA},
pages = {2111--2129},
url = {https://www.usenix.org/conference/nsdi26/presentation/fang},
publisher = {USENIX Association},
month = may
}
