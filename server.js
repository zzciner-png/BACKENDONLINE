// ==========================================
// 🔄 CARREGAMENTO DE VARIÁVEIS DE AMBIENTE
// ==========================================
import dotenv from "dotenv";
dotenv.config();

console.log("✅ Arquivo .env carregado com sucesso\n");

// ==========================================
// 📦 IMPORTAÇÕES
// ==========================================
import express from "express";
import admin from "firebase-admin";
import cors from "cors";
import compression from "compression";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

// ==========================================
// ⚙️ CONFIGURAÇÃO INICIAL - PORTA
// ==========================================

const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin-secret-key-insegura-mude-em-producao";

console.log("🔧 Configuração Inicial:");
console.log(`   🌍 Porta: ${PORT}`);
console.log(`   🌐 Ambiente: ${NODE_ENV}`);
console.log(`   🔗 Frontend URL: ${FRONTEND_URL}`);
console.log(`   🔐 Admin Auth: ${ADMIN_SECRET !== "admin-secret-key-insegura-mude-em-producao" ? "✅ Configurada" : "⚠️  Usar padrão"}\n`);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("📋 Variáveis de Ambiente Carregadas:");
console.log(`   🌍 Frontend URL: ${FRONTEND_URL}`);
console.log(`   📡 Database URL: ${process.env.FIREBASE_DATABASE_URL ? "✅ Definida" : "❌ Não definida"}`);
console.log(`   🔑 Firebase Credentials: ${process.env.FIREBASE_CREDENTIALS ? "✅ Definida" : "❌ Não definida"}`);
console.log(`   🌐 Ambiente: ${NODE_ENV}\n`);
console.log("=".repeat(70) + "\n");

// ==========================================
// 🚀 INICIALIZAÇÃO DO EXPRESS
// ==========================================

const app = express();

// ==========================================
// 🛡️ SEGURANÇA - HELMET
// ==========================================

app.use(helmet());
console.log("✅ Helmet habilitado para proteção de headers\n");

// ==========================================
// 🚦 RATE LIMITING - PROTEÇÃO CONTRA ABUSO
// ==========================================

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // limite de 100 requisições por IP
  message: "Muitas requisições deste IP, tente novamente mais tarde",
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // limite de 10 tentativas de login/cadastro
  message: "Muitas tentativas de autenticação, tente novamente mais tarde",
  skipSuccessfulRequests: true,
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 30, // limite de 30 requisições admin por minuto
  message: "Limite de requisições administrativas excedido",
});

app.use(limiter);
console.log("✅ Rate limiting habilitado\n");

// ==========================================
// 🔓 CONFIGURAR CORS - PERMITIR FRONTEND
// ==========================================

const allowedOrigins = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:8080",
  "http://127.0.0.1:8080",
  "http://localhost:3001",
  "http://localhost:3000",
];

if (NODE_ENV === "production" && FRONTEND_URL && FRONTEND_URL !== "http://localhost:3000") {
  allowedOrigins.push(FRONTEND_URL);
} else if (NODE_ENV === "development") {
  allowedOrigins.push(FRONTEND_URL);
}

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`🚫 CORS bloqueado para origin: ${origin}`);
      callback(new Error("CORS não permitido para este origin"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 3600
}));

console.log("✅ CORS habilitado para:");
allowedOrigins.forEach(origin => console.log(`   - ${origin}`));
console.log();

// ==========================================
// 📦 MIDDLEWARES
// ==========================================

app.use(compression());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

// ==========================================
// 📝 LOG MIDDLEWARE
// ==========================================

app.use((req, res, next) => {
  const timestamp = new Date().toLocaleTimeString('pt-AO');
  const origin = req.get('origin') || 'N/A';
  console.log(`📩 [${timestamp}] ${req.method} ${req.path} - Origin: ${origin} - IP: ${req.ip}`);
  next();
});

// ==========================================
// 🔐 MIDDLEWARE DE AUTENTICAÇÃO ADMIN
// ==========================================

const verifyAdminToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    console.warn("⚠️  Admin: Token não fornecido");
    return res.status(401).json({ 
      success: false,
      error: "Acesso negado",
      message: "Token de administrador não fornecido"
    });
  }

  const token = authHeader.replace("Bearer ", "");

  if (token !== ADMIN_SECRET) {
    console.warn(`⚠️  Admin: Token inválido - ${req.path}`);
    return res.status(403).json({ 
      success: false,
      error: "Acesso negado",
      message: "Token de administrador inválido"
    });
  }

  console.log(`✅ Admin autenticado para: ${req.path}`);
  next();
};

// ==========================================
// 🔐 INICIALIZAR FIREBASE ADMIN
// ==========================================

let firebaseInitialized = false;
let databaseConnected = false;

console.log("🔄 Inicializando Firebase Admin...\n");

function initializeFirebase() {
  try {
    let serviceAccount;

    if (process.env.FIREBASE_CREDENTIALS) {
      console.log("🔑 Usando credenciais do arquivo .env (PRODUÇÃO)");
      try {
        serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
      } catch (parseError) {
        console.error("❌ Erro ao fazer parse das credenciais JSON:");
        console.error(`   ${parseError.message}`);
        return false;
      }
    } else if (fs.existsSync("./serviceAccountKey.json")) {
      console.log("🔑 Usando arquivo serviceAccountKey.json local (DESENVOLVIMENTO)");
      const fileContent = fs.readFileSync("./serviceAccountKey.json", "utf8");
      serviceAccount = JSON.parse(fileContent);
    } else {
      console.error("❌ Nenhuma credencial do Firebase encontrada!");
      console.error("   ⚠️  Configure uma das opções:");
      console.error("   1. PRODUÇÃO: Defina FIREBASE_CREDENTIALS no arquivo .env");
      console.error("   2. DESENVOLVIMENTO: Coloque serviceAccountKey.json na raiz\n");
      return false;
    }

    const databaseURL = process.env.FIREBASE_DATABASE_URL;

    if (!databaseURL) {
      console.error("❌ FIREBASE_DATABASE_URL não foi definido no .env");
      return false;
    }

    console.log(`📡 Database URL: ${databaseURL}`);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: databaseURL
    });

    firebaseInitialized = true;
    console.log("✅ Firebase Admin inicializado com sucesso\n");
    return true;

  } catch (error) {
    console.error("❌ Erro ao inicializar Firebase Admin:");
    console.error(`   ${error.message}\n`);
    return false;
  }
}

if (!initializeFirebase()) {
  console.error("❌ Servidor não pode iniciar sem Firebase configurado corretamente");
  process.exit(1);
}

const db = admin.database();
const auth = admin.auth();

// ==========================================
// 🧪 VALIDAR CONEXÃO COM FIREBASE DATABASE
// ==========================================

console.log("🧪 Testando conexão com Firebase Database...\n");

db.ref("test_connection").set({ status: "ok", timestamp: new Date().toISOString() })
  .then(() => {
    databaseConnected = true;
    console.log("✅ Conexão com Firebase Database confirmada");
    console.log("   ✓ Teste de escrita bem-sucedido\n");
  })
  .catch(err => {
    databaseConnected = false;
    console.error("❌ Erro ao conectar ao Firebase Database:");
    console.error(`   ${err.message}`);
    console.error("   ⚠️  Verifique as credenciais e a URL do banco de dados\n");
    process.exit(1);
  });

// ==========================================
// ✅ FUNÇÕES DE VALIDAÇÃO
// ==========================================

const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const isValidUID = (uid) => {
  return uid && uid.length >= 20 && uid.length <= 128;
};

const isValidPassword = (password) => {
  return password && password.length >= 6;
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ==========================================
// 📋 FUNÇÃO DE LOG ADMINISTRATIVO
// ==========================================

const logAdminAction = async (actionType, targetUid, adminInfo, details = {}, status = "success") => {
  try {
    const logEntry = {
      action: actionType,
      targetUid: targetUid,
      admin: adminInfo || "sistema",
      status: status,
      timestamp: new Date().toISOString(),
      details: details,
      ipAddress: details.ip || "N/A"
    };
    
    const logId = `${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
    await db.ref(`admin_logs/${logId}`).set(logEntry);
    
    console.log(`📋 [${actionType}] Admin log registrado: ${targetUid}`);
  } catch (error) {
    console.error("⚠️  Erro ao registrar log administrativo:", error.message);
  }
};

// ==========================================
// 🏥 ROTA DE HEALTH CHECK
// ==========================================

app.get("/health", (req, res) => {
  console.log("✅ Health check realizado");
  res.status(200).json({ 
    status: "ok", 
    port: PORT,
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    firebaseConnected: firebaseInitialized,
    databaseConnected: databaseConnected,
    corsEnabled: true,
    securityEnabled: true,
    uptime: process.uptime(),
    message: "🚀 Servidor funcionando corretamente"
  });
});

// ==========================================
// 📝 ROTA DE CADASTRO DE USUÁRIO
// ==========================================

app.post("/cadastrarUsuario", authLimiter, asyncHandler(async (req, res) => {
  console.log("📝 Requisição de cadastro de usuário recebida");
  
  const { nome, email, senha, agentCodeRef } = req.body;

  // Validações
  if (!nome || !email || !senha) {
    console.warn("⚠️  Cadastro: Campos obrigatórios faltando");
    return res.status(400).json({ 
      success: false, 
      message: "Dados incompletos - nome, email e senha são obrigatórios" 
    });
  }

  if (!isValidEmail(email)) {
    console.warn(`⚠️  Cadastro: Email inválido - ${email}`);
    return res.status(400).json({ 
      success: false, 
      message: "Email inválido" 
    });
  }

  if (!isValidPassword(senha)) {
    console.warn("⚠️  Cadastro: Senha fraca");
    return res.status(400).json({ 
      success: false, 
      message: "Senha deve ter no mínimo 6 caracteres" 
    });
  }

  if (nome.length < 3) {
    console.warn(`⚠️  Cadastro: Nome muito curto - ${nome}`);
    return res.status(400).json({ 
      success: false, 
      message: "Nome deve ter no mínimo 3 caracteres" 
    });
  }

  try {
    // Verificar se email já existe
    const existingUser = await db.ref("users")
      .orderByChild("email")
      .equalTo(email)
      .limitToFirst(1)
      .once("value");

    if (existingUser.exists()) {
      console.warn(`⚠️  Cadastro: Email já registrado - ${email}`);
      return res.status(409).json({ 
        success: false, 
        message: "Email já registrado" 
      });
    }

    // Criar usuário no Firebase Authentication
    const userRecord = await auth.createUser({
      email,
      password: senha,
      displayName: nome
    });

    const agentCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    const refererUid = agentCodeRef ? await getReferrerUidByCode(agentCodeRef) : null;

    // Preparar dados do usuário
    const userData = {
      uid: userRecord.uid,
      nome,
      email,
      status: "ativo",
      isBanned: false,
      banReason: null,
      banDate: null,
      balance: 200,
      agentCode,
      referrerUid: refererUid || null,
      phone: null,
      earnings: {
        today: 0,
        total: 0,
        commission: 0,
        investment: 0,
        subsidies: 0
      },
      investments: {},
      withdrawals: {},
      deposits: {},
      friends: {
        invested: {},
        registered: refererUid ? { [refererUid]: true } : {}
      },
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Salvar no Database
    await db.ref("users/" + userRecord.uid).set(userData);
    await db.ref("agentCodes/" + agentCode).set(userRecord.uid);

    // Se tem referrador, adicionar à lista de amigos dele
    if (refererUid) {
      await db.ref(`users/${refererUid}/friends/registered/${userRecord.uid}`).set(true);
    }

    console.log(`✅ Usuário cadastrado com sucesso: ${email} (${userRecord.uid}) - Código: ${agentCode}`);

    res.status(201).json({ 
      success: true,
      message: "Usuário cadastrado com sucesso!",
      uid: userRecord.uid,
      agentCode: agentCode,
      email: email,
      nome: nome,
      balance: 200
    });

  } catch (error) {
    console.error("❌ Erro ao cadastrar usuário:", error.message);
    
    if (error.code === "auth/email-already-exists") {
      return res.status(409).json({ 
        success: false, 
        message: "Email já registrado no sistema" 
      });
    }

    res.status(500).json({ 
      success: false, 
      message: "Erro ao cadastrar usuário: " + error.message 
    });
  }
}));

// ==========================================
// 🔄 FUNÇÃO AUXILIAR - OBTER UID POR CÓDIGO DE AGENTE
// ==========================================

const getReferrerUidByCode = async (agentCode) => {
  try {
    const snapshot = await db.ref("agentCodes/" + agentCode).once("value");
    return snapshot.exists() ? snapshot.val() : null;
  } catch (error) {
    console.error("Erro ao obter referrador:", error.message);
    return null;
  }
};

// ==========================================
// 🔐 ROTAS DE AUTENTICAÇÃO
// ==========================================

app.get("/", (req, res) => {
  console.log("✅ Requisição raiz processada");
  res.json({
    message: "🚀 API Nzila Hub v2.1",
    status: "online",
    environment: NODE_ENV,
    version: "2.1.0",
    timestamp: new Date().toISOString(),
    firebaseConnected: firebaseInitialized,
    databaseConnected: databaseConnected,
    port: PORT,
    corsEnabled: true,
    securityEnabled: true,
    features: [
      "Autenticação Firebase",
      "Rate Limiting",
      "Helmet Security",
      "Admin Authentication",
      "Auditoria completa"
    ],
    endpoints: {
      health: "/health",
      public: [
        "/cadastrarUsuario (POST)",
        "/login (POST)"
      ],
      user: [
        "/usuario/:uid (GET)",
        "/saques/:uid (GET)",
        "/depositos/:uid (GET)"
      ],
      admin: [
        "/atualizarStatus (POST)",
        "/aprovarSaque (POST)",
        "/aprovarDeposito (POST)",
        "/banirUsuario (POST)",
        "/desbanirUsuario (POST)",
        "/removerUsuario/:uid (DELETE)",
        "/usuarios (GET)",
        "/stats (GET)",
        "/admin-logs (GET)"
      ]
    }
  });
});

app.post("/login", authLimiter, asyncHandler(async (req, res) => {
  console.log("🔐 Requisição de login recebida");
  
  const { email, senha } = req.body;

  if (!email || !senha) {
    console.warn("⚠️  Login: Email ou senha faltando");
    return res.status(400).json({ success: false, message: "Email e senha são obrigatórios" });
  }

  if (!isValidEmail(email)) {
    console.warn(`⚠️  Login: Email inválido - ${email}`);
    return res.status(400).json({ success: false, message: "Email inválido" });
  }

  try {
    const usersRef = db.ref("users");
    const snapshot = await usersRef
      .orderByChild("email")
      .equalTo(email)
      .limitToFirst(1)
      .once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Login: Usuário não encontrado - ${email}`);
      return res.status(401).json({ success: false, message: "Usuário não encontrado" });
    }

    let userId = null;
    let userData = null;

    snapshot.forEach((child) => {
      userId = child.key;
      userData = child.val();
    });

    // Verificar ban
    if (userData.isBanned === true) {
      console.warn(`🚫 Login rejeitado: Usuário banido - ${userId}`);
      return res.status(403).json({
        success: false,
        message: "Conta banida",
        banned: true,
        banReason: userData.banReason || "Violação dos Termos de Serviço",
        banDate: userData.banDate
      });
    }

    // Verificar suspensão
    if (userData.status === "suspended") {
      console.warn(`🚫 Login: Usuário suspenso - ${userId}`);
      return res.status(403).json({
        success: false,
        message: "Conta suspensa temporariamente",
        suspended: true
      });
    }

    const customToken = await auth.createCustomToken(userId);

    // Atualizar último login
    await db.ref("users/" + userId).update({
      lastLogin: new Date().toISOString()
    });

    console.log(`✅ Login bem-sucedido: ${email} (${userId})`);

    res.json({
      success: true,
      ok: true,
      uid: userId,
      token: customToken,
      userData: {
        nome: userData.nome,
        email: userData.email,
        status: userData.status,
        balance: userData.balance || 0,
        agentCode: userData.agentCode,
        earnings: userData.earnings || {},
        createdAt: userData.createdAt
      }
    });

  } catch (error) {
    console.error("❌ Erro no login:", error.message);
    res.status(500).json({ success: false, message: "Erro ao fazer login" });
  }
}));

// ==========================================
// 👤 ROTAS DE USUÁRIO - CONSULTAS
// ==========================================

app.get("/usuario/:uid", asyncHandler(async (req, res) => {
  const { uid } = req.params;
  console.log(`👤 Requisição para obter dados do usuário: ${uid}`);

  if (!isValidUID(uid)) {
    console.warn(`⚠️  UID inválido: ${uid}`);
    return res.status(400).json({ success: false, error: "UID inválido" });
  }

  try {
    const snapshot = await db.ref("users/" + uid).once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    const userData = snapshot.val();
    console.log(`✅ Dados do usuário obtidos: ${uid}`);

    res.json({ 
      success: true,
      ok: true,
      data: userData 
    });

  } catch (error) {
    console.error(`❌ Erro ao obter usuário ${uid}:`, error.message);
    res.status(500).json({ success: false, error: "Erro ao obter dados do usuário" });
  }
}));

// ==========================================
// 💰 ROTAS DE SAQUES
// ==========================================

app.get("/saques/:uid", asyncHandler(async (req, res) => {
  const { uid } = req.params;
  console.log(`💰 Requisição para obter saques do usuário: ${uid}`);

  if (!isValidUID(uid)) {
    console.warn(`⚠️  UID inválido: ${uid}`);
    return res.status(400).json({ success: false, error: "UID inválido" });
  }

  try {
    const snapshot = await db.ref("saques/" + uid).once("value");

    if (!snapshot.exists()) {
      console.log(`ℹ️  Nenhum saque encontrado para: ${uid}`);
      return res.status(200).json({ success: true, ok: true, data: {} });
    }

    console.log(`✅ Saques obtidos para: ${uid}`);

    res.json({ 
      success: true,
      ok: true,
      data: snapshot.val() 
    });

  } catch (error) {
    console.error(`❌ Erro ao obter saques de ${uid}:`, error.message);
    res.status(500).json({ success: false, error: "Erro ao obter saques do usuário" });
  }
}));

app.post("/aprovarSaque", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  const { uid, valor } = req.body;
  console.log(`💵 Requisição para aprovar saque: ${uid} - Valor: ${valor}`);

  if (!uid || !valor) {
    console.warn("⚠️  UID ou valor faltando");
    return res.status(400).json({ success: false, error: "UID e valor são obrigatórios" });
  }

  if (typeof valor !== "number" || valor <= 0) {
    console.warn(`⚠️  Valor inválido: ${valor}`);
    return res.status(400).json({ success: false, error: "Valor deve ser um número positivo" });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    const userData = snapshot.val();

    if (userData.balance < valor) {
      console.warn(`⚠️  Saldo insuficiente para ${uid}: ${userData.balance} < ${valor}`);
      return res.status(400).json({ success: false, error: "Saldo insuficiente para este saque" });
    }

    const saqueId = `saq_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const saqueData = {
      id: saqueId,
      uid,
      valor,
      status: "aprovado",
      approvedAt: new Date().toISOString(),
      requestedAt: new Date().toISOString()
    };

    await userRef.update({
      balance: userData.balance - valor,
      updatedAt: new Date().toISOString()
    });

    await db.ref("saques/" + uid + "/" + saqueId).set(saqueData);

    await logAdminAction("SAQUE_APROVADO", uid, "admin", { saqueId, valor, ip: req.ip });

    console.log(`✅ Saque aprovado: ${uid} - ID: ${saqueId} - Valor: ${valor} Kz`);

    res.json({ 
      success: true,
      ok: true,
      saqueId,
      message: `Saque de ${valor} Kz aprovado com sucesso`,
      novoBalance: userData.balance - valor
    });

  } catch (error) {
    console.error(`❌ Erro ao aprovar saque de ${uid}:`, error.message);
    await logAdminAction("SAQUE_ERRO", uid, "admin", { erro: error.message }, "error");
    res.status(500).json({ success: false, error: "Erro ao aprovar saque" });
  }
}));

// ==========================================
// 🏦 ROTAS DE DEPÓSITOS
// ==========================================

app.get("/depositos/:uid", asyncHandler(async (req, res) => {
  const { uid } = req.params;
  console.log(`🏦 Requisição para obter depósitos do usuário: ${uid}`);

  if (!isValidUID(uid)) {
    console.warn(`⚠️  UID inválido: ${uid}`);
    return res.status(400).json({ success: false, error: "UID inválido" });
  }

  try {
    const snapshot = await db.ref("depositos/" + uid).once("value");

    if (!snapshot.exists()) {
      console.log(`ℹ️  Nenhum depósito encontrado para: ${uid}`);
      return res.status(200).json({ success: true, ok: true, data: {} });
    }

    console.log(`✅ Depósitos obtidos para: ${uid}`);

    res.json({ 
      success: true,
      ok: true,
      data: snapshot.val() 
    });

  } catch (error) {
    console.error(`❌ Erro ao obter depósitos de ${uid}:`, error.message);
    res.status(500).json({ success: false, error: "Erro ao obter depósitos do usuário" });
  }
}));

app.post("/aprovarDeposito", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  const { uid, valor } = req.body;
  console.log(`🏦 Requisição para aprovar depósito: ${uid} - Valor: ${valor}`);

  if (!uid || !valor) {
    console.warn("⚠️  UID ou valor faltando");
    return res.status(400).json({ success: false, error: "UID e valor são obrigatórios" });
  }

  if (typeof valor !== "number" || valor <= 0) {
    console.warn(`⚠️  Valor inválido: ${valor}`);
    return res.status(400).json({ success: false, error: "Valor deve ser um número positivo" });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    const userData = snapshot.val();
    const depositoId = `dep_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const novoBalance = userData.balance + valor;

    const depositoData = {
      id: depositoId,
      uid,
      valor,
      status: "aprovado",
      approvedAt: new Date().toISOString(),
      requestedAt: new Date().toISOString()
    };

    await userRef.update({
      balance: novoBalance,
      updatedAt: new Date().toISOString()
    });

    await db.ref("depositos/" + uid + "/" + depositoId).set(depositoData);

    await logAdminAction("DEPOSITO_APROVADO", uid, "admin", { depositoId, valor, ip: req.ip });

    console.log(`✅ Depósito aprovado: ${uid} - ID: ${depositoId} - Valor: ${valor} Kz`);

    res.json({ 
      success: true,
      ok: true,
      depositoId,
      message: `Depósito de ${valor} Kz aprovado com sucesso`,
      novoBalance: novoBalance
    });

  } catch (error) {
    console.error(`❌ Erro ao aprovar depósito de ${uid}:`, error.message);
    await logAdminAction("DEPOSITO_ERRO", uid, "admin", { erro: error.message }, "error");
    res.status(500).json({ success: false, error: "Erro ao aprovar depósito" });
  }
}));

// ==========================================
// ⚙️ ROTAS ADMINISTRATIVAS
// ==========================================

app.post("/atualizarStatus", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  const { uid, status } = req.body;
  console.log(`🔄 Requisição para atualizar status: ${uid} → ${status}`);

  if (!uid || !status) {
    console.warn("⚠️  UID ou status faltando");
    return res.status(400).json({ success: false, error: "UID e status são obrigatórios" });
  }

  const validStatuses = ["ativo", "suspenso", "inativo"];
  if (!validStatuses.includes(status)) {
    console.warn(`⚠️  Status inválido: ${status}`);
    return res.status(400).json({ success: false, error: `Status deve ser um de: ${validStatuses.join(", ")}` });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    await userRef.update({
      status,
      updatedAt: new Date().toISOString()
    });

    await logAdminAction("STATUS_ATUALIZADO", uid, "admin", { novoStatus: status, ip: req.ip });

    console.log(`✅ Status atualizado com sucesso: ${uid} → ${status}`);

    res.json({ 
      success: true,
      ok: true,
      message: `Status atualizado para: ${status}`
    });

  } catch (error) {
    console.error(`❌ Erro ao atualizar status de ${uid}:`, error.message);
    res.status(500).json({ success: false, error: "Erro ao atualizar status" });
  }
}));

app.post("/banirUsuario", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  const { uid, motivo } = req.body;
  console.log(`🚫 Requisição para banir usuário: ${uid} - Motivo: ${motivo}`);

  if (!uid) {
    console.warn("⚠️  UID faltando");
    return res.status(400).json({ success: false, error: "UID é obrigatório" });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    const banCode = "BAN-" + Math.random().toString(36).substring(2, 8).toUpperCase();
    const banData = {
      status: "banned",
      isBanned: true,
      banReason: motivo || "Violação dos Termos de Serviço",
      banDate: new Date().toISOString(),
      banCode: banCode,
      updatedAt: new Date().toISOString()
    };

    await userRef.update(banData);

    await logAdminAction("USUARIO_BANIDO", uid, "admin", { motivo, banCode, ip: req.ip });

    console.log(`✅ Usuário banido: ${uid} - Código: ${banCode} - Motivo: ${motivo}`);

    res.json({ 
      success: true,
      ok: true,
      message: `Usuário ${uid} foi banido com sucesso`,
      banCode: banCode,
      banData: banData
    });

  } catch (error) {
    console.error(`❌ Erro ao banir usuário ${uid}:`, error.message);
    res.status(500).json({ success: false, error: "Erro ao banir usuário" });
  }
}));

app.post("/desbanirUsuario", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  const { uid } = req.body;
  console.log(`✅ Requisição para debanir usuário: ${uid}`);

  if (!uid) {
    console.warn("⚠️  UID faltando");
    return res.status(400).json({ success: false, error: "UID é obrigatório" });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    await userRef.update({
      status: "ativo",
      isBanned: false,
      banReason: null,
      banDate: null,
      banCode: null,
      updatedAt: new Date().toISOString()
    });

    await logAdminAction("USUARIO_DEBANIDO", uid, "admin", { ip: req.ip });

    console.log(`✅ Usuário debanido com sucesso: ${uid}`);

    res.json({ 
      success: true,
      ok: true,
      message: `Usuário ${uid} foi debanido com sucesso`
    });

  } catch (error) {
    console.error(`❌ Erro ao debanir usuário ${uid}:`, error.message);
    res.status(500).json({ success: false, error: "Erro ao debanir usuário" });
  }
}));

app.delete("/removerUsuario/:uid", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  const { uid } = req.params;
  console.log(`🗑️  Requisição para remover usuário: ${uid}`);

  if (!isValidUID(uid)) {
    console.warn(`⚠️  UID inválido: ${uid}`);
    return res.status(400).json({ success: false, error: "UID inválido" });
  }

  try {
    const userData = await db.ref("users/" + uid).once("value");
    if (!userData.exists()) {
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    await auth.deleteUser(uid);
    console.log(`✅ Usuário deletado do Firebase Auth: ${uid}`);

    await db.ref("users/" + uid).remove();
    await db.ref("saques/" + uid).remove();
    await db.ref("depositos/" + uid).remove();

    const userDataValue = userData.val();
    if (userDataValue.agentCode) {
      await db.ref("agentCodes/" + userDataValue.agentCode).remove();
    }

    await logAdminAction("USUARIO_REMOVIDO", uid, "admin", { ip: req.ip });

    console.log(`✅ Dados do usuário deletados do Database: ${uid}`);

    res.json({ 
      success: true,
      ok: true,
      message: "Usuário removido com sucesso",
      uid: uid
    });

  } catch (error) {
    console.error(`❌ Erro ao remover usuário ${uid}:`, error.message);
    res.status(500).json({ success: false, error: "Erro ao remover usuário" });
  }
}));

app.get("/usuarios", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  console.log("📋 Requisição para listar usuários");

  try {
    const snapshot = await db.ref("users").limitToFirst(100).once("value");
    
    if (!snapshot.exists()) {
      console.log("ℹ️  Nenhum usuário encontrado");
      return res.json({ success: true, ok: true, total: 0, data: [] });
    }

    const usuarios = [];
    snapshot.forEach((child) => {
      const data = child.val();
      usuarios.push({
        uid: child.key,
        nome: data.nome,
        email: data.email,
        status: data.status,
        balance: data.balance,
        isBanned: data.isBanned,
        banReason: data.banReason || null,
        banDate: data.banDate || null,
        agentCode: data.agentCode,
        createdAt: data.createdAt,
        lastLogin: data.lastLogin
      });
    });

    console.log(`✅ ${usuarios.length} usuários listados`);

    res.json({ success: true, ok: true, total: usuarios.length, data: usuarios });

  } catch (error) {
    console.error("❌ Erro ao listar usuários:", error.message);
    res.status(500).json({ success: false, error: "Erro ao listar usuários" });
  }
}));

app.get("/stats", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  console.log("📊 Requisição para estatísticas");

  try {
    const usersSnapshot = await db.ref("users").once("value");
    const saquesSnapshot = await db.ref("saques").once("value");
    const depositosSnapshot = await db.ref("depositos").once("value");
    const logsSnapshot = await db.ref("admin_logs").limitToLast(100).once("value");

    let totalUsers = 0;
    let totalBalance = 0;
    let bannedUsers = 0;
    let activeUsers = 0;
    let suspendedUsers = 0;

    if (usersSnapshot.exists()) {
      usersSnapshot.forEach((child) => {
        const data = child.val();
        totalUsers++;
        totalBalance += data.balance || 0;
        if (data.isBanned === true) {
          bannedUsers++;
        }
        if (data.status === "ativo") {
          activeUsers++;
        }
        if (data.status === "suspended") {
          suspendedUsers++;
        }
      });
    }

    const stats = {
      totalUsers,
      activeUsers,
      suspendedUsers,
      bannedUsers,
      inactiveUsers: totalUsers - activeUsers - suspendedUsers - bannedUsers,
      totalBalance: parseFloat(totalBalance.toFixed(2)),
      saques: saquesSnapshot.exists() ? Object.keys(saquesSnapshot.val()).length : 0,
      depositos: depositosSnapshot.exists() ? Object.keys(depositosSnapshot.val()).length : 0,
      adminLogs: logsSnapshot.exists() ? Object.keys(logsSnapshot.val()).length : 0,
      timestamp: new Date().toISOString()
    };

    console.log(`✅ Estatísticas obtidas: ${totalUsers} usuários, ${bannedUsers} banidos, ${activeUsers} ativos`);

    res.json({
      success: true,
      ok: true,
      stats: stats
    });

  } catch (error) {
    console.error("❌ Erro ao obter estatísticas:", error.message);
    res.status(500).json({ success: false, error: "Erro ao obter estatísticas" });
  }
}));

app.get("/admin-logs", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  console.log("📋 Requisição para obter logs administrativos");
  const { limit = 50, action } = req.query;

  try {
    let query = db.ref("admin_logs").limitToLast(parseInt(limit) || 50);
    const snapshot = await query.once("value");
    
    if (!snapshot.exists()) {
      console.log("ℹ️  Nenhum log administrativo encontrado");
      return res.json({ success: true, ok: true, data: [] });
    }

    const logs = [];
    snapshot.forEach((child) => {
      const logData = child.val();
      if (!action || logData.action === action) {
        logs.push({
          id: child.key,
          ...logData
        });
      }
    });

    console.log(`✅ ${logs.length} logs administrativos obtidos`);

    res.json({ success: true, ok: true, total: logs.length, data: logs.reverse() });

  } catch (error) {
    console.error("❌ Erro ao obter logs administrativos:", error.message);
    res.status(500).json({ success: false, error: "Erro ao obter logs administrativos" });
  }
}));

// ==========================================
// 🔍 ROTA DE BUSCA DE USUÁRIO
// ==========================================

app.get("/buscar-usuario/:email", verifyAdminToken, adminLimiter, asyncHandler(async (req, res) => {
  const { email } = req.params;
  console.log(`🔍 Busca de usuário por email: ${email}`);

  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, error: "Email inválido" });
  }

  try {
    const snapshot = await db.ref("users")
      .orderByChild("email")
      .equalTo(email)
      .limitToFirst(1)
      .once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${email}`);
      return res.status(404).json({ success: false, error: "Usuário não encontrado" });
    }

    let usuario = null;
    snapshot.forEach((child) => {
      usuario = {
        uid: child.key,
        ...child.val()
      };
    });

    console.log(`✅ Usuário encontrado: ${email}`);

    res.json({
      success: true,
      ok: true,
      data: usuario
    });

  } catch (error) {
    console.error("❌ Erro ao buscar usuário:", error.message);
    res.status(500).json({ success: false, error: "Erro ao buscar usuário" });
  }
}));

// ==========================================
// ⚠️ TRATAMENTO DE ERROS
// ==========================================

app.use((err, req, res, next) => {
  console.error("❌ Erro não tratado:", err.message);
  console.error(err.stack);
  
  res.status(err.status || 500).json({
    success: false,
    error: err.message || "Erro interno do servidor",
    timestamp: new Date().toISOString(),
    environment: NODE_ENV
  });
});

app.use((req, res) => {
  console.warn(`⚠️  Rota não encontrada: ${req.method} ${req.path}`);
  res.status(404).json({
    success: false,
    error: "Rota não encontrada",
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// 🚀 INICIAR SERVIDOR
// ==========================================

const server = app.listen(PORT, () => {
  const timestamp = new Date().toLocaleTimeString('pt-AO');
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║  🚀 Servidor Nzila Hub v2.1 INICIADO COM SUCESSO              ║
╠════════════════════════════════════════════════════════════════╣
║  ⏰ Horário:           ${timestamp}                              ║
║  🔌 Porta:            ${PORT}                                   ║
║  🌍 Ambiente:         ${NODE_ENV}                               ║
║  🔐 Firebase:         ${firebaseInitialized ? "✅ Inicializado" : "❌ Erro"}                   ║
║  📡 Database:         ${databaseConnected ? "✅ Conectado" : "⚠️  Verificar"}                     ║
║  🔓 CORS:             ✅ Habilitado                            ║
║  🛡️  Segurança:        ✅ Helmet + Rate Limiting              ║
║  🔐 Admin Auth:       ✅ Ativada                              ║
║  📋 Auditoria:        ✅ Completa                             ║
║  📝 URL Base:         http://localhost:${PORT}                 ║
║  🏥 Health:           http://localhost:${PORT}/health          ║
╚════════════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("\n🛑 SIGTERM recebido. Encerrando servidor gracefully...");
  server.close(() => {
    console.log("✅ Servidor encerrado");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("\n🛑 SIGINT recebido. Encerrando servidor gracefully...");
  server.close(() => {
    console.log("✅ Servidor encerrado");
    process.exit(0);
  });
});