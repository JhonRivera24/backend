import User from '../models/User.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
const { sign, verify } = jwt;
import crypto from 'crypto';

const register = async (req, res) => {
  const { username, password, securityQuestion, securityAnswer } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedAnswer = await bcrypt.hash(securityAnswer, 10);

    const user = new User({
      username,
      password: hashedPassword,
      securityQuestion,
      securityAnswer: hashedAnswer
    });

    await user.save();
    res.status(201).json({ message: 'Usuario registrado' });
  } catch (error) {
  console.error('Error al registrar usuario:', error); // <- imprime error completo
  res.status(500).json({ message: 'Error al registrar usuario', error: error.message });
}

};

const JWT_SECRET = 'tu_clave_secreta_aquifhfhfhfffhf'; // mejor usar variable de entorno

const login = async (req, res) => {
  const { username, password } = req.body;
  const secretKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // clave para cifrar

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const data = JSON.stringify({ name: user.username });

    const iv = crypto.randomBytes(16);


    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv); // iv debe ser fijo o guardado
let encrypted = cipher.update(data, 'utf8', 'hex');
encrypted += cipher.final('hex');

 const token = sign(
  { data: encrypted },
  'tu_clave_secreta_aquifhfhfhfffhf',
  {
    algorithm: 'HS256',
    expiresIn: '1m'
  }
);

const refreshToken = sign(
  { name: user.username },
  'tu_clave_secreta_aquifhfhfhfffhf',
  {
    algorithm: 'HS256',
    expiresIn: '5m'
  }
);


    // 🍪 Guardar el refreshToken en una cookie HttpOnly
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true, // ✅ En local pon esto en false si no usas HTTPS
      sameSite: 'None',
      maxAge: 5 * 60 * 1000 // ⏱️ 5 minutos en milisegundos (para testing)
    });

    // Enviar el accessToken al frontend
    res.json({ message: 'Login exitoso', token,refreshToken });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
};
const refreshToken = async (req, res) => {
  const { refreshToken } = req.body; // Cambiado para esperar refreshToken en el body
  
  console.log ("Refresh token recibido:", refreshToken);

  if (!refreshToken) {
    return res.status(401).json({ 
      error: "Token de refresco no proporcionado",
      solution: "Asegúrate de enviar el refreshToken en el cuerpo de la solicitud (JSON)"
    });
  }

  try {
    const decoded = jwt.verify(refreshToken, 'tu_clave_secreta_aquifhfhfhfffhf');

    const newAccessToken = sign(
      { name: decoded.name },
      'tu_clave_secreta_aquifhfhfhfffhf',
      {
        algorithm: 'HS256',
        expiresIn: '1m'
      }
    );

    return res.json({ 
      success: true,
      token: newAccessToken,
      expiresIn: "1 minuto"
    });

  } catch (err) {
    console.error("Error al verificar el refresh token:", err);
    
    let errorMessage = "Token inválido";
    if (err.name === 'TokenExpiredError') {
      errorMessage = "Token expirado";
    } else if (err.name === 'JsonWebTokenError') {
      errorMessage = "Token malformado";
    }

    return res.status(403).json({ 
      error: errorMessage,
      details: err.message
    });
  }
};

const getSecurityQuestion = async (req, res) => {
  const { username } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

  res.json({ question: user.securityQuestion });
};

const validateSecurityAnswer = async (req, res) => {
  const { username, answer } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    const isCorrectAnswer = await bcrypt.compare(answer, user.securityAnswer);
    if (!isCorrectAnswer) return res.status(403).json({ message: 'Respuesta incorrecta' });

    res.json({ message: 'Respuesta correcta' });
  } catch (err) {
    console.error('Error al validar respuesta:', err);
    res.status(500).json({ message: 'Error del servidor', error: err.message });
  }
};


// Cambiar contraseña (sin validar la respuesta)
const resetPassword = async (req, res) => {
  const { username, newPassword } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: 'Contraseña actualizada correctamente' });
  } catch (err) {
    console.error('Error al cambiar la contraseña:', err);
    res.status(500).json({ message: 'Error del servidor', error: err.message });
  }
};

export default {
  register,
  login,
  refreshToken,
  getSecurityQuestion,
  resetPassword,
  validateSecurityAnswer
};
