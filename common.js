// ============================================================
// common.js  -  مشترك بين كل الصفحات
// حمّله في كل صفحة قبل أي سكريبت تاني:
//   <script src="common.js"></script>
// ============================================================

// عنوان الـ API في مكان واحد (غيّره هنا بس)
const API_URL = "http://localhost:8004";

// ---------- حماية XSS ----------
// استخدمها مع أي نص جاي من يوزر قبل ما تحطه في innerHTML
function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// ---------- اليوزر والتوكن ----------
function getUser() {
    try {
        return JSON.parse(localStorage.getItem("user"));
    } catch (e) {
        localStorage.removeItem("user");
        return null;
    }
}

function getToken() {
    return localStorage.getItem("token");
}

function saveSession(user, token) {
    localStorage.setItem("user", JSON.stringify(user));
    if (token) localStorage.setItem("token", token);
}

function clearSession() {
    localStorage.removeItem("user");
    localStorage.removeItem("token");
}

// لو مفيش يوزر مسجل يحوّله على صفحة الدخول ويرجّع null
function requireLogin() {
    const user = getUser();
    if (!user || !getToken()) {
        clearSession();
        window.location.href = "login.html";
        return null;
    }
    return user;
}

// للصفحات الخاصة بالأدمن
function requireAdmin() {
    const user = requireLogin();
    if (user && user.role !== "admin") {
        window.location.href = "dashboard.html";
        return null;
    }
    return user;
}

function logout() {
    clearSession();
    window.location.href = "index.html";
}

// ---------- طلبات الـ API ----------
// بتضيف التوكن تلقائيًا. بترجّع { ok, status, data }
async function apiFetch(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (options.body && !headers["Content-Type"] && !(options.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
    }
    const token = getToken();
    if (token) headers["Authorization"] = "Bearer " + token;

    const response = await fetch(API_URL + path, Object.assign({}, options, { headers }));
    let data = null;
    try {
        data = await response.json();
    } catch (e) {
        /* الرد مش JSON */
    }
    if (response.status === 401 && token) {
        // التوكن منتهي أو غلط
        clearSession();
        window.location.href = "login.html";
    }
    return { ok: response.ok, status: response.status, data };
}

// زي apiFetch بس بتعرض رسالة خطأ لوحدها، ولو في successMsg بتعرضها لما ينجح
async function call(path, options = {}, successMsg = "") {
    try {
        const res = await apiFetch(path, options);
        if (!res.ok) {
            toast((res.data && res.data.detail) || "Something went wrong", "error");
        } else if (successMsg) {
            toast(successMsg, "success");
        }
        return res;
    } catch (e) {
        toast("Cannot connect to server", "error");
        return { ok: false, status: 0, data: null };
    }
}

// ---------- أدوات عرض ----------
function toast(message, type = "info") {
    let box = document.getElementById("toastBox");
    if (!box) {
        box = document.createElement("div");
        box.id = "toastBox";
        document.body.appendChild(box);
    }
    const el = document.createElement("div");
    el.className = "toast" + (type === "error" ? " toast-error" : type === "success" ? " toast-success" : "");
    el.textContent = message;
    box.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

function initial(name) {
    return escapeHtml((name || "?").trim().charAt(0).toUpperCase());
}

// نجوم التقييم. avg ممكن تكون null لو مفيش تقييمات
function stars(avg, count) {
    if (avg === null || avg === undefined || !count) {
        return '<span class="muted small">No reviews yet</span>';
    }
    const full = Math.round(Number(avg));
    return `<span class="stars" title="${Number(avg).toFixed(1)} / 5">${"★".repeat(full)}${"☆".repeat(5 - full)}</span> ` +
           `<span class="small muted">${Number(avg).toFixed(1)} (${count})</span>`;
}

function formatDate(value) {
    if (!value) return "";
    const d = new Date(value);
    return isNaN(d) ? "" : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

// رابط الفيديو. الفيديو المعتمد متاح للكل، وغير المعتمد بيحتاج التوكن (صاحبه أو الأدمن)
function videoUrl(id, withToken = false) {
    const token = getToken();
    return `${API_URL}/api/videos/${id}/file` + (withToken && token ? `?token=${encodeURIComponent(token)}` : "");
}

// ---------- النوافذ المنبثقة ----------
function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.hidden = false;
}
function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.hidden = true;
}
// اقفل أي نافذة لو داس برّاها
document.addEventListener("click", function (e) {
    if (e.target.classList && e.target.classList.contains("modal-backdrop")) e.target.hidden = true;
});

// ---------- الهيدر الموحد ----------
// حط في الصفحة:  <div id="app-header"></div>
// وبعدها:        renderHeader('search');   (اسم الصفحة الحالية)
function renderHeader(activePage) {
    const target = document.getElementById("app-header");
    if (!target) return;

    const user = getUser();
    let links = [["index", "index.html", "Home"], ["search", "search.html", "Search"]];
    if (user) {
        links = links.concat([
            ["dashboard", "dashboard.html", "Dashboard"],
            ["swaps", "swaps.html", "My Swaps"],
            ["chat", "chat.html", "Messages"],
        ]);
        if (user.role === "admin") links.push(["admin", "admin.html", "Admin"]);
    }

    const linksHtml = links
        .map(([key, href, label]) =>
            `<a href="${href}" class="${key === activePage ? "active" : ""}">${label}` +
            (key === "chat" ? '<span id="navMsgBadge" class="nav-badge" hidden></span>' : "") + `</a>`
        )
        .join("");

    const authHtml = user
        ? `<span class="nav-user">👋 ${escapeHtml(user.name)}</span>
           <a href="#" id="logoutBtn" class="logout-btn">Logout</a>`
        : `<a href="login.html" class="${activePage === "login" ? "active" : ""}">Login</a>
           <a href="register.html" class="join-btn">Join Now</a>`;

    target.innerHTML = `
        <header class="app-header">
            <a href="index.html" class="logo"><span>Skill</span> <span>Swap</span></a>
            <nav class="nav">${linksHtml}${authHtml}</nav>
        </header>`;

    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", function (e) {
            e.preventDefault();
            logout();
        });
    }

    // عدد الرسائل غير المقروءة
    if (user && getToken()) {
        apiFetch("/api/messages/unread-count").then(res => {
            const badge = document.getElementById("navMsgBadge");
            if (badge && res.ok && res.data && res.data.unread > 0) {
                badge.textContent = res.data.unread;
                badge.hidden = false;
            }
        }).catch(() => {});
    }
}
