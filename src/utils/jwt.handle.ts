import pkg from "jsonwebtoken";
const { sign, verify } = pkg; 
const JWT_SECRET = process.env.JWT_SECRET || "token.010101010101"; // Clave para firmar los tokens de acceso
const REFRESH_SECRET = process.env.REFRESH_SECRET || "refresh.010101010101"; // Clave para firmar refresh token

// Generar token de acceso con ID de usuario y correo electrónico
const generateToken = (id: string, email: string) => {
    const jwt = sign({ id, email }, JWT_SECRET, { expiresIn: '20s' }); 
    return jwt;
};

// Generar un token de actualización que contenga únicamente el ID de usuario.
const generateRefreshToken = (id: string) => {
    const refreshToken = sign({ id }, REFRESH_SECRET, { expiresIn: '10s' }); 
    return refreshToken;
};

// Verificar la validez del token de acceso
const verifyToken = (jwt: string) => {
    const isOk = verify(jwt, JWT_SECRET); 
    return isOk;
};

// Verificar la validez del refresh token 
const verifyRefreshToken = (refreshToken: string) => {
    const isOk = verify(refreshToken, REFRESH_SECRET);
    return isOk;
};

export { generateToken, generateRefreshToken, verifyToken, verifyRefreshToken };