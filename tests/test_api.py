from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app

def client():
    settings = Settings(data_dir="./data-test", household_hash_salt="test-salt")
    return TestClient(create_app(settings))

def test_health():
    res = client().get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

def test_check_high():
    res = client().post("/api/check", json={"content": "URGENT Chase account locked. Verify now https://chase-login.help-verify.ru send your password", "household_id": "hh-1"})
    assert res.status_code == 200
    body = res.json()
    assert body["verdict"] == "HIGH"
    assert body["policy"]["links_opened"] is False

def test_rejects_empty():
    res = client().post("/api/check", json={"content": ""})
    assert res.status_code == 400
