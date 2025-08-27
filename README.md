# Goose IDRS

This repository contains the code for an Intrusion Detection System for substations, using data augmentation and machine learning models.

## Getting Started

### Prerequisites

- Python 3.x
- Jupyter Notebook or JupyterLab

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Halberto/goose-idsr.git
   cd goose-idsr
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Data Augmentation

To augment the data, run the `augmentation_framework.ipynb` notebook located in the `augmentation_framework` directory. This notebook will generate an augmented dataset and save it to `notebook/dataset/augmented_data.csv`.

## Modeling and Analysis

The `notebook` directory contains two main notebooks for modeling and analysis:

1. **`Lightgbm&XAI.ipynb`**: This notebook trains a LightGBM model on the augmented data and provides explainable AI (XAI) insights into the model's predictions.
2. **`Nordsec.ipynb`**: This notebook explores different models and techniques for intrusion detection.

To run these notebooks, start Jupyter Notebook or JupyterLab from the root directory of the project and open the notebooks from the `notebook` directory.

## Dependencies

The required Python libraries are listed in the `requirements.txt` file.
