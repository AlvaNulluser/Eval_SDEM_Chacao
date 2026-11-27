from conftest import auth


def test_index_and_static_assets_are_served(client):
    index = client.get("/")
    assert index.status_code == 200
    assert "SDEM Chacao" in index.text

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "escapeHtml" in script.text


def test_login_returns_token_and_level(client):
    response = client.post("/api/login", json={"username": "admin", "password": "Admin#2026"})
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "Administrador"
    assert body["level"] == 4
    assert body["token"]


def test_login_locks_account_after_three_failures(client):
    for _ in range(2):
        response = client.post("/api/login", json={"username": "empleado", "password": "incorrecta"})
        assert response.status_code == 401

    response = client.post("/api/login", json={"username": "empleado", "password": "incorrecta"})
    assert response.status_code == 403

    # Aun con la contraseña correcta la cuenta queda bloqueada.
    response = client.post("/api/login", json={"username": "empleado", "password": "Empleado#2026"})
    assert response.status_code == 403


def test_analyze_requires_token(client):
    response = client.post("/api/analyze-url", json={"url": "https://example.com"})
    assert response.status_code == 401


def test_analyze_url_with_invalid_port_does_not_crash(client):
    headers = auth(client, "analista", "Analista#2026")
    response = client.post("/api/analyze-url", json={"url": "http://sitio.com:abc/login"}, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"Seguro", "Sospechoso", "Malicioso"}
    assert any("Puerto inválido" in finding for finding in body["findings"])


def test_auditor_cannot_analyze(client):
    headers = auth(client, "auditor", "Auditor#2026")
    response = client.post("/api/analyze-url", json={"url": "https://example.com"}, headers=headers)
    assert response.status_code == 403


def test_empleado_cannot_read_dashboard(client):
    headers = auth(client, "empleado", "Empleado#2026")
    response = client.get("/api/dashboard", headers=headers)
    assert response.status_code == 403


def test_analista_reads_dashboard_metrics(client):
    headers = auth(client, "analista", "Analista#2026")
    client.post("/api/analyze-url", json={"url": "https://www.dhl.com/ve-es/home.html"}, headers=headers)

    response = client.get("/api/dashboard", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["metrics"]["total"] == 1
    assert data["metrics"]["seguros"] == 1
    assert data["recent"][0]["url"] == "https://www.dhl.com/ve-es/home.html"


def test_email_analysis_preserves_link_order(client):
    headers = auth(client, "empleado", "Empleado#2026")
    content = "Primero https://a.example, luego http://b.example y al final https://c.example"
    response = client.post("/api/analyze-email", json={"content": content}, headers=headers)
    assert response.status_code == 200
    urls = [item["url"] for item in response.json()["results"]]
    assert urls == ["https://a.example", "http://b.example", "https://c.example"]


def test_create_user_rejects_weak_password(client):
    headers = auth(client, "admin", "Admin#2026")
    response = client.post(
        "/api/users",
        json={"username": "nuevo", "password": "debil", "role": "Empleado"},
        headers=headers,
    )
    assert response.status_code == 400
    assert "Contraseña débil" in response.json()["detail"]


def test_create_user_forbidden_for_analista(client):
    headers = auth(client, "analista", "Analista#2026")
    response = client.post(
        "/api/users",
        json={"username": "nuevo", "password": "Nuevo#2026", "role": "Empleado"},
        headers=headers,
    )
    assert response.status_code == 403


def test_create_user_allows_login_with_assigned_role(client):
    headers = auth(client, "admin", "Admin#2026")
    response = client.post(
        "/api/users",
        json={"username": "nuevo", "password": "Nuevo#2026", "role": "Auditor"},
        headers=headers,
    )
    assert response.status_code == 200

    response = client.post("/api/login", json={"username": "nuevo", "password": "Nuevo#2026"})
    assert response.status_code == 200
    assert response.json()["level"] == 2


def test_company_registration_requires_analista(client):
    auditor = auth(client, "auditor", "Auditor#2026")
    response = client.post(
        "/api/companies",
        json={"name": "Empresa", "lat": 10.4967, "lon": -66.8537},
        headers=auditor,
    )
    assert response.status_code == 403

    analista = auth(client, "analista", "Analista#2026")
    response = client.post(
        "/api/companies",
        json={"name": "Empresa", "lat": 10.4967, "lon": -66.8537},
        headers=analista,
    )
    assert response.status_code == 200
