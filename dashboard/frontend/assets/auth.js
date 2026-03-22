// Centralized auth utilities for all dashboard pages

const Auth = (() => {
    const TOKEN_KEY = "waf_token";
    const USER_KEY  = "waf_user";

    function saveSession(token, user) {
        localStorage.setItem(TOKEN_KEY, token);
        localStorage.setItem(USER_KEY, JSON.stringify(user));
    }

    function getToken() {
        return localStorage.getItem(TOKEN_KEY);
    }

    function getUser() {
        try {
            return JSON.parse(localStorage.getItem(USER_KEY));
        } catch {
            return null;
        }
    }

    function clearSession() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
    }

    async function logout() {
        const token = getToken();
        if (token) {
            await fetch("/api/auth/logout", {
                method: "POST",
                headers: { "Authorization": "Bearer " + token },
            }).catch(() => {});
        }
        clearSession();
        window.location.href = "/login.html";
    }

    // Redirect to login if not authenticated.
    // Call this at the top of every protected page.
    function requireAuth() {
        const token = getToken();
        const user  = getUser();
        if (!token || !user) {
            window.location.href = "/login.html";
            return null;
        }
        return user;
    }

    // Returns auth headers for fetch() calls
    function headers() {
        return {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + (getToken() || ""),
        };
    }

    // Fetch wrapper that auto-redirects on 401
    async function apiFetch(url, options = {}) {
        const res = await fetch(url, {
            ...options,
            headers: { ...Auth.headers(), ...(options.headers || {}) },
        });
        if (res.status === 401) {
            clearSession();
            window.location.href = "/login.html";
            return null;
        }
        return res;
    }

    // Inject sidebar + topbar into the page.
    // Call after DOMContentLoaded with the active page key.
    function renderShell(activePage) {
        const user = requireAuth();
        if (!user) return;

        const isAdmin = user.role === "admin";

        const navLinks = [
            { key: "dashboard", href: "/",           icon: "grid-2x2",    label: "Dashboard" },
            { key: "logs",      href: "/logs.html",   icon: "scroll-text", label: "Attack Logs" },
            { key: "rules",     href: "/rules.html",  icon: "shield-cog",  label: "Custom Rules" },
            { key: "alerts",    href: "/alerts.html", icon: "bell",        label: "Alerts" },
        ];

        const adminLinks = [
            { key: "users", href: "/users.html", icon: "users", label: "Users & Roles" },
        ];

        function navItem(link) {
            const active = activePage === link.key ? "active" : "";
            return `
                <a href="${link.href}" class="nav-item ${active}">
                    <svg class="nav-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        ${getIconPath(link.icon)}
                    </svg>
                    <span>${link.label}</span>
                </a>`;
        }

        const avatarHtml = user.avatar_url
            ? `<img src="${user.avatar_url}" alt="avatar" class="user-avatar-img">`
            : `<div class="user-avatar-fallback">${(user.username || "U")[0].toUpperCase()}</div>`;

        const roleClass = user.role === "admin" ? "role-admin" : "role-viewer";

        const sidebarHtml = `
            <aside class="sidebar" id="sidebar">
                <div class="sidebar-brand">
                    <svg class="brand-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    <div class="brand-text">
                        <span class="brand-title">WAF Dashboard</span>
                        <span class="brand-sub">Security Control</span>
                    </div>
                </div>

                <nav class="sidebar-nav">
                    <div class="nav-section-label">Main</div>
                    ${navLinks.map(navItem).join("")}
                    ${isAdmin ? `
                    <div class="nav-section-label">Admin</div>
                    ${adminLinks.map(navItem).join("")}
                    ` : ""}
                </nav>

                <div class="sidebar-footer">
                    <div class="sidebar-user">
                        ${avatarHtml}
                        <div class="sidebar-user-info">
                            <span class="sidebar-username">${user.username || "User"}</span>
                            <span class="sidebar-role ${roleClass}">${user.role}</span>
                        </div>
                    </div>
                    <button class="logout-btn" onclick="Auth.logout()" title="Logout">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                            <polyline points="16 17 21 12 16 7"/>
                            <line x1="21" y1="12" x2="9" y2="12"/>
                        </svg>
                    </button>
                </div>
            </aside>`;

        // Insert sidebar before the .main element
        const main = document.querySelector(".main");
        if (main) {
            main.insertAdjacentHTML("beforebegin", sidebarHtml);
        } else {
            document.body.insertAdjacentHTML("afterbegin", sidebarHtml);
        }

        // Inject shared CSS if not already present
        if (!document.getElementById("auth-shell-css")) {
            const style = document.createElement("style");
            style.id = "auth-shell-css";
            style.textContent = getShellCSS();
            document.head.appendChild(style);
        }
    }

    function getIconPath(icon) {
        const paths = {
            "grid-2x2":    `<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>`,
            "scroll-text": `<path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="9" x2="16" y2="9"/>`,
            "shield-cog":  `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><circle cx="12" cy="12" r="2"/><path d="M12 8v1M12 15v1M8.5 10l.87.5M14.63 13.5l.87.5M8.5 14l.87-.5M14.63 10.5l.87-.5"/>`,
            "bell":        `<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>`,
            "users":       `<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>`,
        };
        return paths[icon] || "";
    }

    function getShellCSS() {
        return `
            /* ====== SIDEBAR SHELL ====== */
            .sidebar {
                width: 240px;
                min-height: 100vh;
                background: linear-gradient(160deg, #1a1f36 0%, #252b47 100%);
                display: flex;
                flex-direction: column;
                position: fixed;
                top: 0;
                left: 0;
                bottom: 0;
                z-index: 200;
                border-right: 1px solid rgba(255,255,255,0.06);
            }

            .sidebar-brand {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 24px 20px 20px;
                border-bottom: 1px solid rgba(255,255,255,0.06);
            }

            .brand-icon {
                width: 34px;
                height: 34px;
                color: #7c8ff0;
                flex-shrink: 0;
            }

            .brand-text {
                display: flex;
                flex-direction: column;
            }

            .brand-title {
                font-size: 14px;
                font-weight: 700;
                color: #fff;
                letter-spacing: 0.3px;
            }

            .brand-sub {
                font-size: 11px;
                color: rgba(255,255,255,0.4);
                margin-top: 1px;
            }

            .sidebar-nav {
                flex: 1;
                padding: 16px 12px;
                overflow-y: auto;
                display: flex;
                flex-direction: column;
                gap: 2px;
            }

            .nav-section-label {
                font-size: 10px;
                font-weight: 600;
                letter-spacing: 0.8px;
                text-transform: uppercase;
                color: rgba(255,255,255,0.3);
                padding: 12px 8px 6px;
            }

            .nav-item {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 10px 12px;
                border-radius: 8px;
                color: rgba(255,255,255,0.55);
                text-decoration: none;
                font-size: 13.5px;
                font-weight: 500;
                transition: background 0.15s, color 0.15s;
            }

            .nav-item:hover {
                background: rgba(255,255,255,0.07);
                color: rgba(255,255,255,0.9);
            }

            .nav-item.active {
                background: rgba(124,143,240,0.18);
                color: #a5b4fc;
                font-weight: 600;
            }

            .nav-item.active .nav-icon {
                color: #a5b4fc;
            }

            .nav-icon {
                width: 17px;
                height: 17px;
                flex-shrink: 0;
                color: inherit;
            }

            .sidebar-footer {
                padding: 14px 16px;
                border-top: 1px solid rgba(255,255,255,0.06);
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .sidebar-user {
                display: flex;
                align-items: center;
                gap: 10px;
                flex: 1;
                min-width: 0;
            }

            .user-avatar-img {
                width: 32px;
                height: 32px;
                border-radius: 50%;
                object-fit: cover;
                flex-shrink: 0;
            }

            .user-avatar-fallback {
                width: 32px;
                height: 32px;
                border-radius: 50%;
                background: linear-gradient(135deg, #667eea, #764ba2);
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 13px;
                font-weight: 700;
                color: #fff;
                flex-shrink: 0;
            }

            .sidebar-user-info {
                display: flex;
                flex-direction: column;
                min-width: 0;
            }

            .sidebar-username {
                font-size: 12.5px;
                font-weight: 600;
                color: rgba(255,255,255,0.85);
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .sidebar-role {
                font-size: 10px;
                font-weight: 600;
                letter-spacing: 0.5px;
                text-transform: uppercase;
                margin-top: 1px;
            }

            .role-admin  { color: #f6a623; }
            .role-viewer { color: rgba(255,255,255,0.35); }

            .logout-btn {
                background: none;
                border: none;
                cursor: pointer;
                padding: 6px;
                border-radius: 6px;
                color: rgba(255,255,255,0.3);
                display: flex;
                align-items: center;
                justify-content: center;
                transition: color 0.15s, background 0.15s;
                flex-shrink: 0;
            }

            .logout-btn:hover {
                color: #fc8181;
                background: rgba(252,129,129,0.1);
            }

            .logout-btn svg {
                width: 16px;
                height: 16px;
            }

            /* Adjust .main to account for fixed sidebar */
            .main {
                margin-left: 240px !important;
            }
        `;
    }

    return { saveSession, getToken, getUser, clearSession, logout, requireAuth, headers, apiFetch, renderShell };
})();
