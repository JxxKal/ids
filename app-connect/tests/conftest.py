import sys
from pathlib import Path

# Die Services im Repo haben kein installierbares Paket — src/ liegt im
# Container flach unter /app/src. Für die Tests denselben Import-Pfad
# herstellen, statt Produktionscode um ein setup.py herumzubiegen.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
