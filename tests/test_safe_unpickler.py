import os
import sys
import io
import json
import pytest
import pickle
import joblib
import base64, hashlib, hmac, time as _time
from fastapi.testclient import TestClient

# Add ml-engine to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../ml-engine")))

# Set environment variable for MODEL_PATH to use a test path
TEST_MODEL_PATH = "test_waf_ensemble_final.pkl"
os.environ["MODEL_PATH"] = TEST_MODEL_PATH
# JWT_SECRET de prueba (get_jwt_secret() lo lee en cada request — fail-closed)
os.environ["JWT_SECRET"] = "test-jwt-secret"


def _admin_jwt(role="admin", expired=False):
    """Genera un JWT HS256 firmado con el secreto de prueba — mismas reglas
    de encoding b64url que jsonwebtoken (dashboard), sin padding."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "userid": 1, "username": "admin", "role": role,
            "exp": int(_time.time()) - 3600 if expired else int(_time.time()) + 3600,
        }).encode()
    ).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(
        hmac.new("test-jwt-secret".encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


AUTH = {"Authorization": f"Bearer {_admin_jwt()}"}

# 1. We must prepare a valid dummy model at TEST_MODEL_PATH so that the initial import of app.py doesn't crash.
class MockLGBM:
    def predict(self, val):
        return [0.1]

class MockMLP:
    def predict_proba(self, val):
        return [[0.9, 0.1]]

class MockScaler:
    def transform(self, val):
        return val

DUMMY_BUNDLE = {
    "lgbm_model": MockLGBM(),
    "mlp_model": MockMLP(),
    "mlp_scaler": MockScaler(),
    "lgbm_features": ["col1", "col2"],
    "mlp_features": ["col1", "col2"],
    "lgbm_encoders": {}
}

# Create the initial dummy bundle
joblib.dump(DUMMY_BUNDLE, TEST_MODEL_PATH)

# Clean up function to be run after tests
def cleanup_test_file():
    if os.path.exists(TEST_MODEL_PATH):
        try:
            os.remove(TEST_MODEL_PATH)
        except OSError:
            pass

# Now import modules.
# Since these files don't exist/implement reload_model yet, this is our TDD RED baseline.
try:
    from safe_unpickler import SafeUnpickler, validate_pickle_safe, SecurityError
except ImportError:
    # Fallback/stub definitions if we are running in RED phase and they do not exist yet.
    # Wait, if we define them here, the test would pass/fail on the assertion rather than the import.
    # But standard TDD RED is to let the import fail or raise ImportError, proving the missing file.
    # Let's import them and let the ImportError bubble up, or we can handle it if we want custom test failures.
    # No, bubbling up is perfect for TDD.
    pass

class MaliciousObject:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

def test_safe_pickle_allowed():
    from safe_unpickler import SafeUnpickler
    # Pickling a safe dictionary with standard safe types (allowed modules)
    safe_data = {"a": [1, 2, 3], "b": "hello", "c": True}
    pkl_bytes = pickle.dumps(safe_data)

    # Should not raise any error
    loaded = SafeUnpickler(io.BytesIO(pkl_bytes)).load()
    assert loaded == safe_data

def test_unsafe_pickle_rejected():
    from safe_unpickler import SafeUnpickler, SecurityError
    # Pickling a malicious object
    malicious = MaliciousObject()
    pkl_bytes = pickle.dumps(malicious)

    # The dynamic guard (find_class) should raise SecurityError
    with pytest.raises(SecurityError):
        SafeUnpickler(io.BytesIO(pkl_bytes)).load()

def test_reload_model_endpoint_invalid_pickle():
    from app import app
    client = TestClient(app)
    
    # Write an unsafe pickle to TEST_MODEL_PATH
    malicious = MaliciousObject()
    pkl_bytes = pickle.dumps(malicious)
    with open(TEST_MODEL_PATH, "wb") as f:
        f.write(pkl_bytes)
        
    # Send reload request
    try:
        response = client.post("/reload_model", headers=AUTH)
        assert response.status_code == 400
        assert "error" in response.json() or "detail" in response.json()
    finally:
        # Restore valid model
        joblib.dump(DUMMY_BUNDLE, TEST_MODEL_PATH)

def test_reload_model_endpoint_success():
    from app import app
    client = TestClient(app)
    
    # Create a safe bundle with whitelisted standard types
    NEW_DUMMY_BUNDLE = {
        "lgbm_model": "new_lgbm_model",
        "mlp_model": "new_mlp_model",
        "mlp_scaler": "new_mlp_scaler",
        "lgbm_features": ["col1_new"],
        "mlp_features": ["col2_new"],
        "lgbm_encoders": {"test": 123}
    }
    
    pkl_bytes = pickle.dumps(NEW_DUMMY_BUNDLE)
    with open(TEST_MODEL_PATH, "wb") as f:
        f.write(pkl_bytes)
        
    try:
        response = client.post("/reload_model", headers=AUTH)
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        
        # Verify global variables in app.py are updated
        import app as app_module
        assert app_module.lgbm_model == "new_lgbm_model"
        assert app_module.mlp_model == "new_mlp_model"
        assert app_module.mlp_scaler == "new_mlp_scaler"
        assert app_module.lgbm_cols == ["col1_new"]
        assert app_module.mlp_cols == ["col2_new"]
        assert app_module.lgbm_encoders == {"test": 123}
    finally:
        # Restore valid model
        joblib.dump(DUMMY_BUNDLE, TEST_MODEL_PATH)
        cleanup_test_file()

def test_reload_model_requires_admin_jwt():
    from app import app
    client = TestClient(app)
    assert client.post("/reload_model").status_code == 401
    assert client.post("/reload_model", headers={"Authorization": "Bearer a.b.c"}).status_code == 401

def test_reload_model_rejects_expired_token():
    from app import app
    client = TestClient(app)
    response = client.post(
        "/reload_model",
        headers={"Authorization": f"Bearer {_admin_jwt(expired=True)}"},
    )
    assert response.status_code == 401

def test_reload_model_rejects_non_admin_role():
    from app import app
    client = TestClient(app)
    response = client.post(
        "/reload_model",
        headers={"Authorization": f"Bearer {_admin_jwt(role='viewer')}"},
    )
    assert response.status_code == 403
