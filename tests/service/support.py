import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "web-app-cst-quality-check"
SCRIPT = ROLE / "files" / "python" / "script.py"


def load_launcher():
    """
    Returns:
        The launcher script imported as the module `launcher`, as the web image ships it.
    """
    if "launcher" in sys.modules:
        return sys.modules["launcher"]
    spec = importlib.util.spec_from_file_location("launcher", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["launcher"] = module
    spec.loader.exec_module(module)
    return module
