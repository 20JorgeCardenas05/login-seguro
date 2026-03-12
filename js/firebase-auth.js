// Flujo cliente del login con Google:
// 1. Inicializa Firebase con la configuracion expuesta por login.php.
// 2. Abre el popup de Google y obtiene el idToken.
// 3. Envia ese token al backend para que el servidor cree la sesion PHP.
(() => {
    const googleBtn   = document.getElementById('btn-google');
    const alertBox    = document.getElementById('firebase-alert');
    const csrfInput   = document.querySelector('input[name="csrf_token"]');
    const config      = window.FIREBASE_CONFIG || {};

    // Refleja visualmente si la autenticacion sigue en curso.
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

    // Muestra errores o advertencias sin depender de alert() del navegador.
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
    // Sin apiKey valida no tiene sentido permitir el clic porque el SDK no
    // podria inicializarse correctamente.
    if (!config.apiKey || (config.apiKey || '').startsWith('REEMPLAZA')) {
        googleBtn.disabled = true;
        showAlert('Configura tus credenciales de Firebase en config/firebase.php para habilitar el login con Google.', 'warning');
        return;
    }

    try {
        // Firebase solo debe inicializarse una vez por pagina.
        firebase.initializeApp(config);
    } catch (e) {
        // Si la app ya estaba inicializada, ignorar el error.
        if (!/already exists/i.test(e.message || '')) {
            showAlert('No se pudo inicializar Firebase: ' + (e.message || e), 'error');
            return;
        }
    }

    // auth administra la sesion temporal del SDK y provider define el uso de Google.
    const auth     = firebase.auth();
    const provider = new firebase.auth.GoogleAuthProvider();
    provider.setCustomParameters({ prompt: 'select_account' });

    // Asegurar que cualquier sesión previa de Firebase se cierre al cargar el login tradicional.
    auth.signOut().catch(() => {});

    googleBtn.addEventListener('click', async (event) => {
        event.preventDefault();
        setButtonState(true);

        try {
            // El popup autentica al usuario con Google y devuelve un objeto de usuario.
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

        // El backend valida tanto el token de Firebase como el CSRF local.
        const respuesta = await fetch('firebase_login.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ idToken, csrf_token: csrf })
        });

        // Si la respuesta no trae JSON valido se degrada a objeto vacio para
        // poder construir un mensaje uniforme de error.
        const data = await respuesta.json().catch(() => ({}));

        // Renovar token CSRF recibido (si lo hay)
        // El backend rota el token CSRF despues de validarlo; aqui se sincroniza.
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
        // Si el backend acepto el token, la sesion PHP ya existe y solo queda navegar.
        window.location.href = data.redirect || 'bienvenida.php';
    }

    // Convierte codigos tecnicos de Firebase en mensajes entendibles para el usuario.
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
