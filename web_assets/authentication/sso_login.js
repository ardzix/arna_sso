(() => {
    "use strict";
    const el = (id) => document.getElementById(id);
    const config = JSON.parse(el("sso-login-config").textContent);
    let mfa = null;
    let otp = null;
    let busy = false;

    function status(message, error = false) {
        el("status").textContent = message || "";
        el("status").classList.toggle("error", error);
    }

    async function request(path, body, access) {
        const headers = {"Accept": "application/json"};
        if (body !== undefined) {
            headers["Content-Type"] = "application/json";
            headers["X-CSRFToken"] = document.querySelector("[name=csrfmiddlewaretoken]").value;
        }
        if (access) headers.Authorization = "Bearer " + access;
        const abort = new AbortController();
        const timer = setTimeout(() => abort.abort(), 15000);
        try {
            const res = await fetch(path, {
                method: body === undefined ? "GET" : "POST", credentials: "same-origin",
                headers, body: JSON.stringify(body), signal: abort.signal, cache: "no-store",
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                const text = [data.detail, data.message, data.error].find((value) => typeof value === "string");
                const error = new Error(text || (res.status === 429 ? "Terlalu banyak percobaan. Coba lagi nanti." : "Permintaan gagal. Coba lagi."));
                error.code = data.error;
                error.httpStatus = res.status;
                throw error;
            }
            return data;
        } finally {
            clearTimeout(timer);
        }
    }

    async function run(work) {
        if (busy) return;
        busy = true;
        const buttons = [...document.querySelectorAll("button:not(:disabled)")];
        buttons.forEach((button) => { button.disabled = true; });
        status("");
        try {
            await work();
        } catch (error) {
            if (error.code === "invalid_session" && mfa) resetMfa();
            status(error.name === "AbortError" ? "Koneksi terlalu lama. Coba lagi." : error.message, true);
        } finally {
            busy = false;
            buttons.forEach((button) => { button.disabled = false; });
        }
    }

    function resetMfa() {
        mfa = null;
        el("mfaForm").hidden = true;
        el("mfaToken").value = "";
        el("methods").hidden = false;
    }

    async function finish(data) {
        if (data.mfa_required && typeof data.token === "string") {
            mfa = data.token;
            el("methods").hidden = true;
            el("mfaForm").hidden = false;
            el("mfaToken").focus();
            status("Masukkan kode dari aplikasi authenticator.");
            return;
        }
        if (typeof data.access !== "string" || !data.access) throw new Error("SSO tidak mengembalikan sesi yang valid.");
        const session = await request("/login/session/", config.pkce || {}, data.access);
        if (typeof session.redirect_url !== "string") throw new Error("SSO tidak mengembalikan tujuan masuk.");
        window.location.assign(session.redirect_url);
    }

    function selectMethod(wa) {
        el("emailMethod").setAttribute("aria-pressed", String(!wa));
        el("waMethod").setAttribute("aria-pressed", String(wa));
        el("passwordForm").hidden = wa;
        el("waForm").hidden = !wa;
        (wa ? el("phone") : el("email")).focus();
        status("");
    }

    el("emailMethod").onclick = () => selectMethod(false);
    el("waMethod").onclick = () => selectMethod(true);
    el("passwordForm").onsubmit = (event) => {
        event.preventDefault();
        run(async () => {
            const data = await request("/api/auth/login/", {email: el("email").value.trim(), password: el("password").value});
            el("password").value = "";
            await finish(data);
        });
    };
    el("mfaForm").onsubmit = (event) => {
        event.preventDefault();
        if (!mfa) return;
        run(async () => finish(await request("/api/auth/mfa/verify/", {token: mfa, mfa_token: el("mfaToken").value})));
    };
    el("cancelMfa").onclick = () => { resetMfa(); status(""); };

    function resetOtp() {
        otp = null;
        el("phone").disabled = false;
        el("waMode").disabled = false;
        el("otp").required = false;
        el("otp").value = "";
        el("waCode").hidden = true;
        el("waReverse").hidden = true;
        el("waChat").removeAttribute("href");
        el("waSubmit").textContent = "Minta kode";
    }
    el("changePhone").onclick = () => { resetOtp(); el("phone").focus(); status(""); };
    el("waForm").onsubmit = (event) => {
        event.preventDefault();
        run(async () => {
            if (otp) {
                const result = await request("/api/auth/wa/verify-otp/", {phone: otp, otp: el("otp").value});
                resetOtp();
                await finish(result);
                return;
            }
            const phone = el("phone").value.replace(/[\s().-]/g, "");
            if (!/^\+?\d{8,15}$/.test(phone)) throw new Error("Masukkan nomor WhatsApp yang valid.");
            const reverse = el("waMode").value === "reverse";
            const data = await request(reverse ? "/api/auth/wa/reverse/send-otp/" : "/api/auth/wa/send-otp/", {phone});
            otp = data.phone || phone;
            el("phone").disabled = true;
            el("waMode").disabled = true;
            el("waCode").hidden = false;
            if (reverse && /^\d{8,15}$/.test(config.reverseWhatsApp)) {
                el("waChat").href = "https://wa.me/" + config.reverseWhatsApp + "?text=OTP";
                el("waReverse").hidden = false;
            }
            el("otp").required = true;
            el("waSubmit").textContent = "Verifikasi kode";
            el("otp").focus();
            status(reverse ? "Kirim pesan OTP melalui tautan WhatsApp." : "Jika nomor terdaftar, kode akan dikirim ke WhatsApp.");
        });
    };

    function decodeBuffer(value) {
        const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
        return Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")), (char) => char.charCodeAt(0));
    }
    function encodeBuffer(buffer) {
        return btoa(Array.from(new Uint8Array(buffer), (value) => String.fromCharCode(value)).join(""))
            .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }
    el("passkeyButton").onclick = () => run(async () => {
        if (!window.PublicKeyCredential || !navigator.credentials) throw new Error("Browser ini belum mendukung passkey.");
        const begin = await request("/api/auth/passkeys/login/begin/");
        const options = begin.publicKey || begin;
        const credential = await navigator.credentials.get({publicKey: {
            ...options, challenge: decodeBuffer(options.challenge),
            allowCredentials: (options.allowCredentials || []).map((item) => ({...item, id: decodeBuffer(item.id)})),
        }});
        if (!credential) throw new Error("Login passkey dibatalkan.");
        const response = credential.response;
        await finish(await request("/api/auth/passkeys/login/complete/", {
            id: credential.id, rawId: encodeBuffer(credential.rawId), type: credential.type,
            response: {authenticatorData: encodeBuffer(response.authenticatorData),
                clientDataJSON: encodeBuffer(response.clientDataJSON), signature: encodeBuffer(response.signature),
                userHandle: response.userHandle ? encodeBuffer(response.userHandle) : null},
        }));
    });

    const google = el("googleButton");
    if (google && config.googleClientId) {
        const script = document.createElement("script");
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.onerror = () => { google.textContent = "Google belum tersedia. Pilih metode lain."; };
        script.onload = () => {
            try {
                window.google.accounts.id.initialize({
                    client_id: config.googleClientId,
                    callback: ({credential}) => run(async () => {
                        if (mfa) return;
                        await finish(await request("/api/auth/google-login/", {token: credential}));
                    }),
                });
                window.google.accounts.id.renderButton(google, {
                    type: "standard", theme: "outline", size: "large", text: "signin_with", locale: "id",
                    width: Math.min(google.clientWidth || 300, 400),
                });
            } catch (_) {
                google.textContent = "Google belum tersedia. Pilih metode lain.";
            }
        };
        document.head.appendChild(script);
    }
})();
