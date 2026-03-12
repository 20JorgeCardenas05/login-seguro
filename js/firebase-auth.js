(() => {
    const googleBtn   = document.getElementById('btn-google');
    const alertBox    = document.getElementById('firebase-alert');
    const csrfInput   = document.querySelector('input[name="csrf_token"]');
    const config      = window.FIREBASE_CONFIG || {};

    const setButtonState = (isLoading) => {
        if (!googleBtn) return;
        if (isLoading) {
            googleBtn.classList.add('btn-loading');
            googleBtn.disabled = true;
            googleBtn.dataset.label = googleBtn.innerHTML;
            googleBtn.innerHTML = '<span class="loader" aria-hidden="true"></span> Conectando...';
        } else {
            googleBtn.classList.remove('btn-loading');
            googleBtn.disabled = false;
            if (googleBtn.dataset.label) {
                googleBtn.innerHTML = googleBtn.dataset.label;
            }
        }
    };

    const showAlert = (text, type = 'error') => {
        if (!alertBox) return;
        alertBox.style.display = 'block';
        alertBox.textContent = text;

        alertBox.className = 'alert';
        if (type === 'success') {
            alertBox.classList.add('alert-success');
        } else if (type === 'warning') {
            alertBox.classList.add('alert-warning');
        } else {
            alertBox.classList.add('alert-error');
        }
    };

    if (!googleBtn) return;

    // Verificar configuración mínima
    if (!config.apiKey || (config.apiKey || '').startsWith('REEMPLAZA')) {
        googleBtn.disabled = true;
        showAlert('Configura tus credenciales de Firebase en config/firebase.php para habilitar el login con Google.', 'warning');
        return;
    }

    try {
        firebase.initializeApp(config);
    } catch (e) {
        // Si la app ya estaba inicializada, ignorar el error.
        if (!/already exists/i.test(e.message || '')) {
            showAlert('No se pudo inicializar Firebase: ' + (e.message || e), 'error');
            return;
        }
    }

    const auth     = firebase.auth();
    const provider = new firebase.auth.GoogleAuthProvider();
    provider.setCustomParameters({ prompt: 'select_account' });

    // Asegurar que cualquier sesión previa de Firebase se cierre al cargar el login tradicional.
    auth.signOut().catch(() => {});

    googleBtn.addEventListener('click', async (event) => {
        event.preventDefault();
        setButtonState(true);

        try {
            const result  = await auth.signInWithPopup(provider);
            const idToken = await result.user.getIdToken();
            await enviarTokenAServidor(idToken);
        } catch (err) {
            const friendly = mapAuthError(err);
            showAlert(friendly, 'error');
            setButtonState(false);
        }
    });

    async function enviarTokenAServidor(idToken) {
        const csrf = csrfInput ? csrfInput.value : '';

        const respuesta = await fetch('firebase_login.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ idToken, csrf_token: csrf })
        });

        const data = await respuesta.json().catch(() => ({}));

        // Renovar token CSRF recibido (si lo hay)
        if (csrfInput && data.csrf_token) {
            csrfInput.value = data.csrf_token;
        }

        if (!respuesta.ok || !data.ok) {
            const mensaje = data.mensaje || 'No se pudo validar el token en el servidor.';
            // Mostrar detalle en consola para depurar (aud/iss/exp/CSRF)
            console.error('firebase_login.php error', { status: respuesta.status, data });
            throw new Error(mensaje);
        }

        // Redirigir usando la ruta provista
        window.location.href = data.redirect || 'bienvenida.php';
    }

    function mapAuthError(error) {
        const code = error && error.code ? error.code : '';
        const base = 'No se pudo iniciar sesión con Google. ';

        switch (code) {
            case 'auth/popup-closed-by-user':
                return base + 'La ventana emergente se cerró antes de finalizar.';
            case 'auth/cancelled-popup-request':
                return base + 'Se canceló la ventana anterior, intenta de nuevo.';
            case 'auth/popup-blocked':
                return base + 'El navegador bloqueó la ventana emergente. Permite popups para este sitio.';
            case 'auth/network-request-failed':
                return base + 'Problema de red, verifica tu conexión.';
            default:
                return base + (error.message || 'Intente nuevamente.');
        }
    }
})();
