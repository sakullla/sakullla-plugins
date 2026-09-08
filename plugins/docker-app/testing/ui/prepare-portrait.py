"""Create a local, transparent portrait study without uploading the reference."""
import argparse
from pathlib import Path
from urllib.request import urlretrieve

import numpy as np
import onnxruntime as ort
from PIL import Image

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("image", type=Path)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[4]
model = repo / ".cache/anime-seg-isnetis.onnx"
model.parent.mkdir(exist_ok=True)
if not model.exists():
    urlretrieve(
        "https://huggingface.co/skytnt/anime-seg/resolve/"
        "976cbb9ba61600e0993d1ee2a8a247ae05d183ee/isnetis.onnx",
        model,
    )
image = Image.open(args.image).convert("RGB")
width, height = image.size
size = 1024
scaled_w = round(width * size / max(width, height))
scaled_h = round(height * size / max(width, height))
x, y = (size - scaled_w) // 2, (size - scaled_h) // 2
tensor = np.zeros((size, size, 3), dtype=np.float32)
tensor[y:y + scaled_h, x:x + scaled_w] = np.asarray(
    image.resize((scaled_w, scaled_h), Image.Resampling.LANCZOS), dtype=np.float32
) / 255
session = ort.InferenceSession(str(model), providers=["CPUExecutionProvider"])
mask = session.run(None, {session.get_inputs()[0].name: tensor.transpose(2, 0, 1)[None]})[0][0, 0]
mask = np.clip(mask[y:y + scaled_h, x:x + scaled_w], 0, 1)
alpha = Image.fromarray((mask * 255).astype("uint8")).resize(image.size, Image.Resampling.LANCZOS)
portrait = image.convert("RGBA")
portrait.putalpha(alpha)
output = repo / "dist/docker-app-live2d-preview/reference"
output.mkdir(parents=True, exist_ok=True)
portrait.save(output / "character.png")
portrait.save(output / "character.webp", lossless=True)
print(f"Saved local portrait {width} × {height}: {output}")
