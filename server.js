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

// ==========================================
// ⚙️ CONFIGURAÇÃO INICIAL - PORTA
// ==========================================

const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

console.log("🔧 Configuração Inicial:");
console.log(`   🌍 Porta: ${PORT}`);
console.log(`   🌐 Ambiente: ${NODE_ENV}`);
console.log(`   🔗 Frontend URL: ${FRONTEND_URL}\n`);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("📋 Variáveis de Ambiente Carregadas:");
console.log(`   🌍 Frontend URL: ${FRONTEND_URL}`);
console.log(`   📡 Database URL: ${process.env.FIREBASE_DATABASE_URL || "usando fallback padrão"}`);
console.log(`   🔑 Firebase Credentials: ${process.env.FIREBASE_CREDENTIALS ? "✅ Definida" : "❌ Não definida"}`);
console.log(`   🌐 Ambiente: ${NODE_ENV}\n`);
console.log("=".repeat(70) + "\n");

// ==========================================
// 🚀 INICIALIZAÇÃO DO EXPRESS
// ==========================================

const app = express();

// ==========================================
// 🔓 CONFIGURAR CORS - PERMITIR FRONTEND
// ==========================================

// PRODUÇÃO: Apenas FRONTEND_URL aprovada
const allowedOrigins = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:8080",
  "http://127.0.0.1:8080",
  "http://localhost:3001",
  "http://localhost:3000",
];

// Adicionar URL do frontend em produção
if (NODE_ENV === "production") {
  if (FRONTEND_URL && FRONTEND_URL !== "http://localhost:3000") {
    allowedOrigins.push(FRONTEND_URL);
  }
} else {
  // Em desenvolvimento, permitir mais locais
  allowedOrigins.push(FRONTEND_URL);
}

app.use(cors({
  origin: (origin, callback) => {
    // Permitir requisições sem origin (como curl, mobile apps, etc)
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
// 📦 MIDDLEWARES - PARSERS NATIVOS DO EXPRESS
// ==========================================

app.use(compression());
// ✅ SUBSTITUIÇÃO: express.json() no lugar de body-parser.json()
app.use(express.json({ limit: "10mb" }));
// ✅ SUBSTITUIÇÃO: express.urlencoded() no lugar de body-parser.urlencoded()
app.use(express.urlencoded({ limit: "10mb", extended: true }));

// ==========================================
// 📝 LOG MIDDLEWARE - REGISTRA CADA REQUISIÇÃO
// ==========================================

app.use((req, res, next) => {
  const timestamp = new Date().toLocaleTimeString('pt-AO');
  const origin = req.get('origin') || 'N/A';
  console.log(`📩 [${timestamp}] ${req.method} ${req.path} - Origin: ${origin} - IP: ${req.ip}`);
  next();
});

// ==========================================
// 🔐 INICIALIZAR FIREBASE ADMIN
// ==========================================

let firebaseInitialized = false;
let databaseConnected = false;

console.log("🔄 Inicializando Firebase Admin...\n");

function initializeFirebase() {
  try {
    let serviceAccount;

    // ✅ PRODUÇÃO: Usar variável de ambiente
    if (process.env.FIREBASE_CREDENTIALS) {
      console.log("🔑 Usando credenciais do arquivo .env (PRODUÇÃO)");
      try {
        serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
      } catch (parseError) {
        console.error("❌ Erro ao fazer parse das credenciais JSON:");
        console.error(`   ${parseError.message}`);
        return false;
      }
    } 
    // ✅ DESENVOLVIMENTO: Usar arquivo local
    else if (fs.existsSync("./serviceAccountKey.json")) {
      console.log("🔑 Usando arquivo serviceAccountKey.json local (DESENVOLVIMENTO)");
      const fileContent = fs.readFileSync("./serviceAccountKey.json", "utf8");
      serviceAccount = JSON.parse(fileContent);
    } 
    else {
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
// 🏥 ROTA DE HEALTH CHECK
// ==========================================

app.get("/health", (req, res) => {
  console.log("✅ Health check realizado");
  res.json({ 
    status: "ok", 
    port: PORT,
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    firebaseConnected: firebaseInitialized,
    databaseConnected: databaseConnected,
    corsEnabled: true,
    uptime: process.uptime(),
    message: "🚀 Servidor funcionando corretamente"
  });
});

// ==========================================
// 📝 ROTA DE CADASTRO DE USUÁRIO
// ==========================================

app.post("/cadastrarUsuario", asyncHandler(async (req, res) => {
  console.log("📝 Requisição de cadastro de usuário recebida");
  
  const { nome, email, senha } = req.body;

  // Validar campos obrigatórios
  if (!nome || !email || !senha) {
    console.warn("⚠️  Cadastro: Campos obrigatórios faltando");
    return res.status(400).json({ 
      success: false, 
      message: "Dados incompletos - nome, email e senha são obrigatórios" 
    });
  }

  // Validar email
  if (!isValidEmail(email)) {
    console.warn(`⚠️  Cadastro: Email inválido - ${email}`);
    return res.status(400).json({ 
      success: false, 
      message: "Email inválido" 
    });
  }

  // Validar senha
  if (!isValidPassword(senha)) {
    console.warn("⚠️  Cadastro: Senha fraca");
    return res.status(400).json({ 
      success: false, 
      message: "Senha deve ter no mínimo 6 caracteres" 
    });
  }

  // Validar nome
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

    // Gerar código de agente
    const agentCode = Math.random().toString(36).substring(2, 10).toUpperCase();

    // Preparar dados do usuário
    const userData = {
      uid: userRecord.uid,
      nome,
      email,
      status: "ativo",
      isBanned: false,
      balance: 200,
      agentCode,
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
        registered: {}
      },
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Salvar no Database
    await db.ref("users/" + userRecord.uid).set(userData);
    await db.ref("agentCodes/" + agentCode).set(userRecord.uid);

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
// 🔐 ROTAS DE AUTENTICAÇÃO
// ==========================================

app.get("/", (req, res) => {
  console.log("✅ Requisição raiz processada");
  res.json({
    message: "🚀 API Nzila Hub v2.0",
    status: "online",
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    firebaseConnected: firebaseInitialized,
    databaseConnected: databaseConnected,
    port: PORT,
    corsEnabled: true,
    endpoints: {
      health: "/health",
      cadastro: "/cadastrarUsuario",
      login: "/login",
      usuario: "/usuario/:uid",
      saques: "/saques/:uid",
      depositos: "/depositos/:uid",
      admin: ["/atualizarStatus", "/aprovarSaque", "/aprovarDeposito", "/banirUsuario", "/removerUsuario/:uid", "/usuarios", "/stats"]
    }
  });
});

app.post("/login", asyncHandler(async (req, res) => {
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

    if (userData.status === "banned" || userData.isBanned === true) {
      console.warn(`🚫 Login rejeitado: Usuário banido - ${userId}`);
      return res.status(403).json({
        success: false,
        message: "Conta banida",
        banned: true,
        banReason: userData.banReason,
        banDate: userData.banDate
      });
    }

    if (userData.status === "suspended") {
      console.warn(`🚫 Login: Usuário suspenso - ${userId}`);
      return res.status(403).json({
        success: false,
        message: "Conta suspensa temporariamente",
        suspended: true
      });
    }

    const customToken = await auth.createCustomToken(userId);

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
        createdAt: userData.createdAt
      }
    });

  } catch (error) {
    console.error("❌ Erro no login:", error.message);
    res.status(500).json({ success: false, message: "Erro ao fazer login: " + error.message });
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
    return res.status(400).json({ error: "UID inválido" });
  }

  try {
    const snapshot = await db.ref("users/" + uid).once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    const userData = snapshot.val();

    console.log(`✅ Dados do usuário obtidos: ${uid}`);

    res.json({ 
      ok: true,
      data: userData 
    });

  } catch (error) {
    console.error(`❌ Erro ao obter usuário ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao obter dados do usuário" });
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
    return res.status(400).json({ error: "UID inválido" });
  }

  try {
    const snapshot = await db.ref("saques/" + uid).once("value");

    if (!snapshot.exists()) {
      console.log(`ℹ️  Nenhum saque encontrado para: ${uid}`);
      return res.status(200).json({ ok: true, data: {} });
    }

    console.log(`✅ Saques obtidos para: ${uid}`);

    res.json({ 
      ok: true,
      data: snapshot.val() 
    });

  } catch (error) {
    console.error(`❌ Erro ao obter saques de ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao obter saques do usuário" });
  }
}));

app.post("/aprovarSaque", asyncHandler(async (req, res) => {
  const { uid, valor } = req.body;
  console.log(`💵 Requisição para aprovar saque: ${uid} - Valor: ${valor}`);

  if (!uid || !valor) {
    console.warn("⚠️  UID ou valor faltando");
    return res.status(400).json({ error: "UID e valor são obrigatórios" });
  }

  if (typeof valor !== "number" || valor <= 0) {
    console.warn(`⚠️  Valor inválido: ${valor}`);
    return res.status(400).json({ error: "Valor deve ser um número positivo" });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    const userData = snapshot.val();

    if (userData.balance < valor) {
      console.warn(`⚠️  Saldo insuficiente para ${uid}: ${userData.balance} < ${valor}`);
      return res.status(400).json({ error: "Saldo insuficiente para este saque" });
    }

    const saqueId = Math.random().toString(36).substring(2, 10);
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

    console.log(`✅ Saque aprovado: ${uid} - ID: ${saqueId} - Valor: ${valor} Kz`);

    res.json({ 
      ok: true,
      saqueId,
      message: `Saque de ${valor} Kz aprovado com sucesso`,
      novoBalance: userData.balance - valor
    });

  } catch (error) {
    console.error(`❌ Erro ao aprovar saque de ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao aprovar saque" });
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
    return res.status(400).json({ error: "UID inválido" });
  }

  try {
    const snapshot = await db.ref("depositos/" + uid).once("value");

    if (!snapshot.exists()) {
      console.log(`ℹ️  Nenhum depósito encontrado para: ${uid}`);
      return res.status(200).json({ ok: true, data: {} });
    }

    console.log(`✅ Depósitos obtidos para: ${uid}`);

    res.json({ 
      ok: true,
      data: snapshot.val() 
    });

  } catch (error) {
    console.error(`❌ Erro ao obter depósitos de ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao obter depósitos do usuário" });
  }
}));

app.post("/aprovarDeposito", asyncHandler(async (req, res) => {
  const { uid, valor } = req.body;
  console.log(`🏦 Requisição para aprovar depósito: ${uid} - Valor: ${valor}`);

  if (!uid || !valor) {
    console.warn("⚠️  UID ou valor faltando");
    return res.status(400).json({ error: "UID e valor são obrigatórios" });
  }

  if (typeof valor !== "number" || valor <= 0) {
    console.warn(`⚠️  Valor inválido: ${valor}`);
    return res.status(400).json({ error: "Valor deve ser um número positivo" });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    const userData = snapshot.val();
    const depositoId = Math.random().toString(36).substring(2, 10);
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

    console.log(`✅ Depósito aprovado: ${uid} - ID: ${depositoId} - Valor: ${valor} Kz`);

    res.json({ 
      ok: true,
      depositoId,
      message: `Depósito de ${valor} Kz aprovado com sucesso`,
      novoBalance: novoBalance
    });

  } catch (error) {
    console.error(`❌ Erro ao aprovar depósito de ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao aprovar depósito" });
  }
}));

// ==========================================
// ⚙️ ROTAS ADMINISTRATIVAS
// ==========================================

app.post("/atualizarStatus", asyncHandler(async (req, res) => {
  const { uid, status } = req.body;
  console.log(`🔄 Requisição para atualizar status: ${uid} → ${status}`);

  if (!uid || !status) {
    console.warn("⚠️  UID ou status faltando");
    return res.status(400).json({ error: "UID e status são obrigatórios" });
  }

  const validStatuses = ["ativo", "suspenso", "inativo", "banned"];
  if (!validStatuses.includes(status)) {
    console.warn(`⚠️  Status inválido: ${status}`);
    return res.status(400).json({ error: `Status deve ser um de: ${validStatuses.join(", ")}` });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    await userRef.update({
      status,
      updatedAt: new Date().toISOString()
    });

    console.log(`✅ Status atualizado com sucesso: ${uid} → ${status}`);

    res.json({ 
      ok: true,
      message: `Status atualizado para: ${status}`
    });

  } catch (error) {
    console.error(`❌ Erro ao atualizar status de ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao atualizar status" });
  }
}));

app.post("/banirUsuario", asyncHandler(async (req, res) => {
  const { uid, motivo } = req.body;
  console.log(`🚫 Requisição para banir usuário: ${uid} - Motivo: ${motivo}`);

  if (!uid) {
    console.warn("⚠️  UID faltando");
    return res.status(400).json({ error: "UID é obrigatório" });
  }

  try {
    const userRef = db.ref("users/" + uid);
    const snapshot = await userRef.once("value");

    if (!snapshot.exists()) {
      console.warn(`⚠️  Usuário não encontrado: ${uid}`);
      return res.status(404).json({ error: "Usuário não encontrado" });
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

    console.log(`✅ Usuário banido: ${uid} - Código: ${banCode}`);

    res.json({ 
      ok: true,
      message: `Usuário ${uid} foi banido com sucesso`,
      banCode: banCode,
      banData: banData
    });

  } catch (error) {
    console.error(`❌ Erro ao banir usuário ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao banir usuário" });
  }
}));

app.delete("/removerUsuario/:uid", asyncHandler(async (req, res) => {
  const { uid } = req.params;
  console.log(`🗑️  Requisição para remover usuário: ${uid}`);

  if (!isValidUID(uid)) {
    console.warn(`⚠️  UID inválido: ${uid}`);
    return res.status(400).json({ error: "UID inválido" });
  }

  try {
    await auth.deleteUser(uid);
    console.log(`✅ Usuário deletado do Firebase Auth: ${uid}`);

    await db.ref("users/" + uid).remove();
    await db.ref("saques/" + uid).remove();
    await db.ref("depositos/" + uid).remove();

    console.log(`✅ Dados do usuário deletados do Database: ${uid}`);

    res.json({ 
      ok: true,
      message: "Usuário removido com sucesso",
      uid: uid
    });

  } catch (error) {
    console.error(`❌ Erro ao remover usuário ${uid}:`, error.message);
    res.status(500).json({ error: "Erro ao remover usuário" });
  }
}));

app.get("/usuarios", asyncHandler(async (req, res) => {
  console.log("📋 Requisição para listar usuários");

  try {
    const snapshot = await db.ref("users").limitToFirst(100).once("value");
    
    if (!snapshot.exists()) {
      console.log("ℹ️  Nenhum usuário encontrado");
      return res.json({ ok: true, total: 0, data: [] });
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
        createdAt: data.createdAt
      });
    });

    console.log(`✅ ${usuarios.length} usuários listados`);

    res.json({ ok: true, total: usuarios.length, data: usuarios });

  } catch (error) {
    console.error("❌ Erro ao listar usuários:", error.message);
    res.status(500).json({ error: "Erro ao listar usuários" });
  }
}));

app.get("/stats", asyncHandler(async (req, res) => {
  console.log("📊 Requisição para estatísticas");

  try {
    const usersSnapshot = await db.ref("users").once("value");
    const saquesSnapshot = await db.ref("saques").once("value");
    const depositosSnapshot = await db.ref("depositos").once("value");

    let totalUsers = 0;
    let totalBalance = 0;
    let bannedUsers = 0;
    let activeUsers = 0;

    if (usersSnapshot.exists()) {
      usersSnapshot.forEach((child) => {
        const data = child.val();
        totalUsers++;
        totalBalance += data.balance || 0;
        if (data.status === "banned") {
          bannedUsers++;
        }
        if (data.status === "ativo") {
          activeUsers++;
        }
      });
    }

    const stats = {
      totalUsers,
      activeUsers,
      bannedUsers,
      totalBalance: totalBalance.toFixed(2),
      saques: saquesSnapshot.exists() ? Object.keys(saquesSnapshot.val()).length : 0,
      depositos: depositosSnapshot.exists() ? Object.keys(depositosSnapshot.val()).length : 0,
      timestamp: new Date().toISOString()
    };

    console.log(`✅ Estatísticas obtidas: ${totalUsers} usuários, ${bannedUsers} banidos, ${activeUsers} ativos`);

    res.json({
      ok: true,
      stats: stats
    });

  } catch (error) {
    console.error("❌ Erro ao obter estatísticas:", error.message);
    res.status(500).json({ error: "Erro ao obter estatísticas" });
  }
}));

// ==========================================
// ⚠️ TRATAMENTO DE ERROS
// ==========================================

app.use((err, req, res, next) => {
  console.error("❌ Erro não tratado:", err.message);
  console.error(err.stack);
  
  res.status(err.status || 500).json({
    error: err.message || "Erro interno do servidor",
    timestamp: new Date().toISOString(),
    environment: NODE_ENV
  });
});

app.use((req, res) => {
  console.warn(`⚠️  Rota não encontrada: ${req.method} ${req.path}`);
  res.status(404).json({
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
╔════════════════════════════════════════════════════════╗
║  🚀 Servidor Nzila Hub INICIADO COM SUCESSO           ║
╠════════════════════════════════════════════════════════╣
║  ⏰ Horário:      ${timestamp}                           ║
║  🔌 Porta:       ${PORT}                                ║
║  🌍 Ambiente:    ${NODE_ENV}                            ║
║  🔐 Firebase:    ${firebaseInitialized ? "✅ Inicializado" : "❌ Erro"}                 ║
║  📡 Database:    ${databaseConnected ? "✅ Conectado" : "⚠️  Verificar"}                   ║
║  🔓 CORS:        ✅ Habilitado                         ║
║  📝 URL Base:    http://localhost:${PORT}              ║
║  🏥 Health:      http://localhost:${PORT}/health       ║
╚════════════════════════════════════════════════════════╝
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