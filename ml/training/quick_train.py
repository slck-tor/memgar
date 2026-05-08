"""
Quick CPU training — 5K examples, 1 epoch → produces a working ONNX model
for local testing without GPU. Full training runs on GPU via CI.
"""
import json, logging, sys
from pathlib import Path
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

DATA = Path("ml/data/training_data.json")
OUT  = Path("ml/artifacts/transformer_model")

# Use a 5K stratified subset
raw = json.loads(DATA.read_text())
attacks = [e for e in raw if e["label"] == 1][:2500]
benign  = [e for e in raw if e["label"] == 0][:2500]
subset  = attacks + benign

subset_path = Path("/tmp/subset_training.json")
subset_path.write_text(json.dumps(subset))
logging.info("Subset: %d examples", len(subset))

from ml.training.transformer_trainer import train
result = train(
    training_data_path=str(subset_path),
    base_model="distilbert-base-uncased",
    num_epochs=1,
    batch_size=64,
    export_onnx=True,
)
print(json.dumps(result, indent=2, default=str))
