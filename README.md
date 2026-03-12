# login-seguro
- Baltazar Jiménez Juan Pablo
- Cardenas Puente Jorge Rafael
- Aldaco Godínez Jorge Emiliano
- Valencia Massaky Santiago

## Autenticación con Firebase (Google)
1. Crea un proyecto en Firebase Console y habilita Authentication → Sign-in method → Google.
2. Copia los valores de configuración web en `config/firebase.php` (también puedes usar variables de entorno).
3. Sirve el sitio bajo HTTPS cuando sea posible; el botón usa `signInWithPopup`.
4. El ID token se valida en el servidor (`firebase_login.php`) antes de crear la sesión PHP tradicional.
