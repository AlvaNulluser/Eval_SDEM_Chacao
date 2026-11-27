let token = null;
let currentUser = null;
let currentLogs = [];
let map = null;
let markersLayer = null;

function authHeaders() {
    return {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
    };
}

// Escapa texto antes de interpolarlo en innerHTML (evita XSS almacenado).
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
}

function canSeeDashboard() {
    return currentUser && currentUser.level >= 2;
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const errBox = document.getElementById("login-error");

    try {
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail);

        token = data.token;
        currentUser = data;
        errBox.classList.add("hidden");
        initApp();
    } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove("hidden");
    }
});

function initApp() {
    document.getElementById("login-screen").classList.add("hidden");
    document.getElementById("app-screen").classList.remove("hidden");
    document.getElementById("user-badge").textContent = `${currentUser.username} · ${currentUser.role}`;

    const lvl = currentUser.level;
    document.getElementById("sec-dashboard").classList.toggle("hidden", lvl < 2);
    document.getElementById("sec-recent").classList.toggle("hidden", lvl < 2);
    document.getElementById("sec-analyzers").classList.toggle("hidden", lvl === 2);
    document.getElementById("sec-map").classList.toggle("hidden", lvl < 2);
    document.getElementById("form-company").classList.toggle("hidden", lvl < 3);
    document.getElementById("sec-users").classList.toggle("hidden", lvl < 4);
    document.getElementById("sec-audit").classList.toggle("hidden", lvl < 2);

    if (lvl >= 2 && !map) {
        map = L.map("map").setView([10.4967, -66.8537], 15);
        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            attribution: "© OpenStreetMap"
        }).addTo(map);
        markersLayer = L.layerGroup().addTo(map);

        map.on("click", (e) => {
            document.getElementById("comp-lat").value = e.latlng.lat.toFixed(4);
            document.getElementById("comp-lon").value = e.latlng.lng.toFixed(4);
        });
    }
    setTimeout(() => { if (map) map.invalidateSize(); }, 200);
    if (canSeeDashboard()) refreshDashboard();
}

function logout() {
    token = null;
    currentUser = null;
    document.getElementById("app-screen").classList.add("hidden");
    document.getElementById("login-screen").classList.remove("hidden");
    document.getElementById("password").value = "";
}

function loadSampleUrl() {
    document.getElementById("url-input").value = "http://seniat-aduana-verificacion.xyz:8080/login@192.168.1.5/factura%20pendiente";
}

function loadSampleEmail() {
    document.getElementById("email-input").value = "Estimado importador, su guía DHL presenta retención en aduana. Valide en http://dhl-tracking-chacao.top/verify o visite https://www.dhl.com";
}

async function analyzeUrl() {
    const url = document.getElementById("url-input").value;
    if (!url) return;
    const res = await fetch("/api/analyze-url", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ url })
    });
    const data = await res.json();
    const box = document.getElementById("url-result");
    if (!res.ok) {
        box.className = "p-4 rounded-lg border text-sm bg-red-50 border-red-400 text-red-800";
        box.textContent = data.detail || "No se pudo analizar el enlace";
        box.classList.remove("hidden");
        return;
    }
    const colors = {
        "Seguro": "bg-emerald-50 border-emerald-400 text-emerald-800",
        "Sospechoso": "bg-amber-50 border-amber-400 text-amber-800",
        "Malicioso": "bg-red-50 border-red-400 text-red-800"
    };
    box.className = `p-4 rounded-lg border text-sm ${colors[data.status] || "bg-slate-50 border-slate-300"}`;
    box.innerHTML = `<strong>Resultado: ${escapeHtml(data.status)} (Riesgo: ${escapeHtml(data.score)}/100)</strong><ul class="list-disc ml-5 mt-1">${data.findings.map(f => `<li>${escapeHtml(f)}</li>`).join("")}</ul>`;
    box.classList.remove("hidden");
    if (canSeeDashboard()) refreshDashboard();
}

async function analyzeEmail() {
    const content = document.getElementById("email-input").value;
    if (!content) return;
    const res = await fetch("/api/analyze-email", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ content })
    });
    const data = await res.json();
    const box = document.getElementById("email-result");
    if (!res.ok) {
        box.textContent = data.detail || "No se pudo analizar el correo";
        return;
    }
    box.innerHTML =
        `<p class="font-semibold">Enlaces detectados: ${escapeHtml(data.extracted_count)}</p>` +
        data.results.map(r => `<div class="p-2 border rounded dark:border-slate-700"><strong>[${escapeHtml(r.status)}]</strong> ${escapeHtml(r.url)} <span class="text-xs text-slate-500">(${escapeHtml(r.findings.join(", "))})</span></div>`).join("");
    if (canSeeDashboard()) refreshDashboard();
}

async function refreshDashboard() {
    const res = await fetch("/api/dashboard", { headers: authHeaders() });
    const data = await res.json();
    if (!res.ok) return;

    document.getElementById("stat-total").textContent = data.metrics.total;
    document.getElementById("stat-seguros").textContent = data.metrics.seguros;
    document.getElementById("stat-sospechosos").textContent = data.metrics.sospechosos;
    document.getElementById("stat-maliciosos").textContent = data.metrics.maliciosos;

    if (data.recent.length) {
        document.getElementById("recent-list").innerHTML = data.recent.map(r =>
            `<div class="flex justify-between border-b dark:border-slate-700 pb-1">
                <span class="truncate max-w-lg">${escapeHtml(r.url)}</span>
                <span class="font-semibold">${escapeHtml(r.status)} (${escapeHtml(r.timestamp)})</span>
            </div>`
        ).join("");
    }

    if (markersLayer) {
        markersLayer.clearLayers();
        data.companies.forEach(c => {
            L.marker([c.lat, c.lon]).addTo(markersLayer)
                .bindPopup(`<b>${escapeHtml(c.name)}</b><br>Lat: ${escapeHtml(c.lat)}, Lon: ${escapeHtml(c.lon)}`);
        });
    }

    currentLogs = data.logs;
    document.getElementById("audit-body").innerHTML = data.logs.map(l =>
        `<tr class="border-b dark:border-slate-700"><td class="py-1.5">${escapeHtml(l.timestamp)}</td><td>${escapeHtml(l.user)}</td><td class="font-medium">${escapeHtml(l.action)}</td><td>${escapeHtml(l.detail)}</td></tr>`
    ).join("");
}

async function registerCompany() {
    const name = document.getElementById("comp-name").value;
    const lat = parseFloat(document.getElementById("comp-lat").value);
    const lon = parseFloat(document.getElementById("comp-lon").value);
    if (!name) return alert("Ingrese el nombre de la empresa");

    await fetch("/api/companies", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ name, lat, lon })
    });
    document.getElementById("comp-name").value = "";
    refreshDashboard();
}

async function createUser() {
    const username = document.getElementById("new-user").value;
    const password = document.getElementById("new-pass").value;
    const role = document.getElementById("new-role").value;

    const res = await fetch("/api/users", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ username, password, role })
    });
    const data = await res.json();
    alert(res.ok ? data.message : data.detail);
    if (res.ok) refreshDashboard();
}

function exportCSV() {
    let csv = "Fecha/Hora,Usuario,Accion,Detalle\n";
    currentLogs.forEach(l => {
        csv += `"${l.timestamp}","${l.user}","${l.action}","${l.detail}"\n`;
    });
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "bitacora_sdem_chacao.csv";
    a.click();
}
