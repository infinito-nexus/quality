import sys

from tests.service.support import ROOT, load_launcher

load_launcher()
sys.path.insert(0, str(ROOT / "service" / "web"))
