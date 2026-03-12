<?php
/**
 * Configuración de Firebase Authentication (lado cliente y servidor)
 * Rellena los valores con los datos de tu proyecto en Firebase Console.
 * Nunca subas a un repositorio público las claves reales de producción.
 */

// Estos valores se usan tanto en el cliente como en el backend. La configuracion
// web de Firebase no reemplaza la validacion del servidor; solo permite iniciar el SDK.
// Puedes sobreescribir estos valores con variables de entorno si lo prefieres.
define('FIREBASE_API_KEY', getenv('FIREBASE_API_KEY') ?: 'AIzaSyAk4zkoumtEXjiBAXj3HTTcZveNHHAADF0');
define('FIREBASE_AUTH_DOMAIN', getenv('FIREBASE_AUTH_DOMAIN') ?: 'login-seguro-d412f.firebaseapp.com');
define('FIREBASE_PROJECT_ID', getenv('FIREBASE_PROJECT_ID') ?: 'login-seguro-d412f');
define('FIREBASE_APP_ID', getenv('FIREBASE_APP_ID') ?: '1:443413324410:web:e39df97d5d32599f0d51c3');
define('FIREBASE_MESSAGING_SENDER_ID', getenv('FIREBASE_MESSAGING_SENDER_ID') ?: '443413324410');
define('FIREBASE_MEASUREMENT_ID', getenv('FIREBASE_MEASUREMENT_ID') ?: 'G-RWMPWF4BGR');

// Metadatos utiles si mas adelante se hace validacion local del JWT ademas de
// la consulta remota a Firebase Identity Toolkit.
/**
 * Identificador esperado en el claim "aud" de los ID Tokens.
 * Para Firebase es, por defecto, el Project ID.
 */
define('FIREBASE_EXPECTED_AUD', FIREBASE_PROJECT_ID);

/**
 * Emisor válido para los ID Tokens de Firebase.
 * Formato: https://securetoken.google.com/<project-id>
 */
define('FIREBASE_EXPECTED_ISS', 'https://securetoken.google.com/login-seguro-d412f');
