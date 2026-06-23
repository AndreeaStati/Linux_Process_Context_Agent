import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
USER_SPACE_DIR = PROJECT_ROOT / "user_space"

sys.path.insert(0, str(USER_SPACE_DIR))
