import pytest

from siem import settings


@pytest.fixture(autouse=True)
def _yaml_engine_on(monkeypatch):
    """Mặc định sản phẩm (R65) tắt engine YAML, nhưng code engine còn nguyên và các test cũ kiểm nó; test về chế độ tắt
    tự đặt RULE_ENGINE_ENABLED=False."""
    monkeypatch.setattr(settings, "RULE_ENGINE_ENABLED", True)
