from app.analysis.urls import analyze_host, is_private_or_local

def test_refuses_private_hosts():
    assert is_private_or_local("127.0.0.1")
    ev = analyze_host("http://127.0.0.1/login", "chase login")
    assert any(e.code == "private_host" for e in ev)

def test_brand_mismatch():
    ev = analyze_host("https://chase-secure.example.xyz/login", "Your Chase account")
    codes = {e.code for e in ev}
    assert "brand_host_mismatch" in codes or "abused_tld" in codes
