import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def stub_model():
    class StubModel:
        def __init__(self):
            class M:
                coef_ = [[0.1, 0.2, 0.3, 0.4]]

            self.model = M()
            self.feature_names = ["f1", "f2", "f3", "f4"]

        def predict_proba(self, samples):
            return [0.7 for _ in samples]

    return StubModel()


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch):
    monkeypatch.setenv("SECUREOPS_SECRET", "test-secret")


@pytest.fixture
def app(monkeypatch, stub_model):
    try:
        import importlib

        ml = importlib.import_module("ai_engine.model_loader")
    except Exception:
        import types

        ml = types.SimpleNamespace(load_or_train_model=lambda force_train=False: None)

    monkeypatch.setattr(ml, "load_or_train_model", lambda force_train=False: stub_model)

    import importlib

    app_module = importlib.import_module("api.fastapi_app")
    create_app = getattr(app_module, "create_app")
    app = create_app()
    return app


@pytest.fixture
def client(app):
    return TestClient(app)
