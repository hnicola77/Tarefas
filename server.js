// server.js - SISTEMA UNIFICADO (EngVR + ChaveVR)
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURAÇÃO DO BANCO DE DADOS (PERSISTÊNCIA RENDER) ---
// Verifica se a pasta /data existe (ambiente Render), senão usa local
const dbDir = fs.existsSync('/data') ? '/data' : __dirname;
const dbPath = path.join(dbDir, 'database_unified.db');

console.log(`Conectando ao banco de dados em: ${dbPath}`);

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("Erro ao conectar no banco:", err);
  else console.log("Banco conectado com sucesso.");
});

// --- MIDDLEWARES ---
app.use(cors());
app.use(express.json());
app.use(session({
  secret: "segredo_super_seguro_mapa_engenharia",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 } // 8 horas
}));

// --- CRIAÇÃO DAS TABELAS ---
db.serialize(() => {
  // 1. Usuários
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  // 2. Demandas (EngVR)
  db.run(`CREATE TABLE IF NOT EXISTS demandas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empreendimento TEXT NOT NULL,
    etapa_setor TEXT,
    item_servico TEXT,
    prioridade TEXT,
    data_obra TEXT,
    solicitacao TEXT,
    mapa_cotacao TEXT,
    pedido_compra TEXT,
    contrato TEXT,
    status_atual TEXT,
    status_fluxo TEXT,
    motivo TEXT,
    observacao TEXT,
    criado_em TEXT,
    atualizado_em TEXT
  )`);

  // 3. Histórico (EngVR)
  db.run(`CREATE TABLE IF NOT EXISTS demandas_historico (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    demanda_id INTEGER,
    data_hora TEXT,
    usuario TEXT,
    tipo TEXT,
    descricao TEXT
  )`);

  // 4. Entregas/Unidades (ChaveVR)
  // Unificamos os nomes: tabela 'entregas' para manter padrão, 
  // mas com campos solicitados no Lote 3/4.
  db.run(`CREATE TABLE IF NOT EXISTS entregas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empreendimento TEXT NOT NULL,
    bloco TEXT NOT NULL,
    unidade TEXT NOT NULL,
    situacao TEXT,
    status_financeiro TEXT,
    habitavel TEXT,
    cvco TEXT,
    chaves_entregues TEXT, 
    data_vistoria TEXT,
    hora_vistoria TEXT,
    agendado_por TEXT,
    data_liberacao TEXT,
    observacao TEXT,
    criado_em TEXT,
    atualizado_em TEXT
  )`);
});

// --- SEGURANÇA E AUTENTICAÇÃO ---

// Rotas abertas
const openRoutes = ["/login.html", "/auth/login", "/styles.css", "/auth/logout"];

// Middleware de verificação de login
app.use((req, res, next) => {
  // Permite arquivos estáticos globais (imagens, css) e rotas abertas
  if (openRoutes.includes(req.path) || req.path.startsWith("/favicon")) {
    return next();
  }

  // Se não estiver logado
  if (!req.session.userId) {
    if (req.path.startsWith("/api")) {
      return res.status(401).json({ error: "Não autenticado" });
    }
    return res.redirect("/login.html");
  }
  next();
});

// Middleware Admin
function requireAdmin(req, res, next) {
  if (req.session.role !== "admin") return res.status(403).json({ error: "Acesso negado" });
  next();
}

// Middleware Manager ou Admin (Para ChaveVR)
function requireManagerOrAdmin(req, res, next) {
  if (!["admin", "manager"].includes(req.session.role)) {
    return res.status(403).json({ error: "Acesso restrito a gestores." });
  }
  next();
}

// --- ROTAS DE AUTH ---
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: "Usuário inválido" });
    
    if (bcrypt.compareSync(password, user.password_hash)) {
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      return res.json({ success: true, role: user.role });
    }
    res.status(401).json({ error: "Senha incorreta" });
  });
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get("/auth/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, username: req.session.username, role: req.session.role });
});

// --- ROTAS USERS (ADMIN) ---
// (Manter lógica básica de criar usuários para você poder logar)
app.get("/api/users", requireAdmin, (req, res) => {
  db.all("SELECT id, username, role FROM users", [], (err, rows) => res.json(rows));
});
app.post("/api/users", requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)", 
    [username, hash, role], function(err) {
      if(err) return res.status(400).json({error: "Erro ou usuário já existe"});
      res.json({id: this.lastID});
  });
});
app.delete("/api/users/:id", requireAdmin, (req, res) => {
    if(req.session.userId == req.params.id) return res.status(400).json({error:"Não se delete"});
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], (err) => res.json({success: true}));
});

// ==========================================
// 🏗️ MÓDULO ENGVR (DEMANDAS)
// ==========================================
app.get("/api/demandas", (req, res) => {
  // Simplificação: Listar todas (adicione filtros se necessário conforme Lote 1)
  let sql = "SELECT * FROM demandas ORDER BY data_obra ASC";
  db.all(sql, [], (err, rows) => {
    if(err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

app.post("/api/demandas", (req, res) => {
  const d = req.body;
  const now = new Date().toISOString();
  // Campos simplificados para brevidade, adicione todos conforme Lote 1
  const sql = `INSERT INTO demandas (empreendimento, etapa_setor, item_servico, prioridade, data_obra, status_atual, status_fluxo, observacao, solicitacao, mapa_cotacao, pedido_compra, contrato, motivo, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;
  const params = [d.empreendimento, d.etapaSetor, d.itemServico, d.prioridade, d.dataEmObra, d.statusAtual, d.statusFluxo || "Aberta", d.observacao, d.solicitacao, d.mapaCotacao, d.pedidoCompra, d.contrato, d.motivo, now, now];
  
  db.run(sql, params, function(err) {
    if(err) return res.status(500).json({error: err.message});
    res.json({id: this.lastID});
  });
});
// (Adicione PUT e DELETE do EngVR aqui conforme necessidade, seguindo o padrão acima)

// ==========================================
// 🔑 MÓDULO CHAVEVR (ENTREGAS/UNIDADES)
// ==========================================

// 1. Listar (GET)
app.get("/api/entregas", requireManagerOrAdmin, (req, res) => {
    db.all("SELECT * FROM entregas ORDER BY empreendimento, bloco, unidade", [], (err, rows) => {
        if(err) return res.status(500).json({error: err.message});
        // Frontend espera campos em camelCase ou direto? O frontend do Lote 4 espera:
        // u.empreendimento, u.bloco... O banco tem colunas exatas?
        // Vamos mapear para garantir compatibilidade com o JS do frontend
        const mapped = rows.map(r => ({
            id: r.id,
            empreendimento: r.empreendimento,
            bloco: r.bloco,
            unidade: r.unidade,
            situacao: r.situacao,
            statusFinanceiro: r.status_financeiro,
            habitavel: r.habitavel,
            cvco: r.cvco,
            chaves: r.chaves_entregues, // JS chama de 'chaves', banco 'chaves_entregues'
            dataVistoria: r.data_vistoria,
            horaVistoria: r.hora_vistoria,
            agendadoPor: r.agendado_por,
            dataLiberacao: r.data_liberacao,
            observacao: r.observacao
        }));
        res.json(mapped);
    });
});

// 2. Criar Individual (POST)
app.post("/api/entregas", requireManagerOrAdmin, (req, res) => {
    const d = req.body;
    const now = new Date().toISOString();
    const sql = `INSERT INTO entregas (empreendimento, bloco, unidade, situacao, status_financeiro, habitavel, cvco, chaves_entregues, data_vistoria, hora_vistoria, agendado_por, data_liberacao, observacao, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;
    
    // Mapeando do JS (camelCase) para o DB (snake_case)
    const params = [d.empreendimento, d.bloco, d.unidade, d.situacao, d.statusFinanceiro, d.habitavel, d.cvco, d.chaves, d.dataVistoria, d.horaVistoria, d.agendadoPor, d.dataLiberacao, d.observacao, now, now];

    db.run(sql, params, function(err){
        if(err) return res.status(500).json({error: err.message});
        res.status(201).json({id: this.lastID});
    });
});

// 3. Atualizar (PUT)
app.put("/api/entregas/:id", requireManagerOrAdmin, (req, res) => {
    const d = req.body;
    const now = new Date().toISOString();
    const sql = `UPDATE entregas SET empreendimento=?, bloco=?, unidade=?, situacao=?, status_financeiro=?, habitavel=?, cvco=?, chaves_entregues=?, data_vistoria=?, hora_vistoria=?, agendado_por=?, data_liberacao=?, observacao=?, atualizado_em=? WHERE id=?`;
    
    const params = [d.empreendimento, d.bloco, d.unidade, d.situacao, d.statusFinanceiro, d.habitavel, d.cvco, d.chaves, d.dataVistoria, d.horaVistoria, d.agendadoPor, d.dataLiberacao, d.observacao, now, req.params.id];

    db.run(sql, params, function(err){
        if(err) return res.status(500).json({error: err.message});
        res.json({success: true});
    });
});

// 4. Excluir (DELETE)
app.delete("/api/entregas/:id", requireManagerOrAdmin, (req, res) => {
    db.run("DELETE FROM entregas WHERE id=?", [req.params.id], function(err){
        if(err) return res.status(500).json({error: err.message});
        res.json({success: true});
    });
});

// 5. CADASTRO EM LOTE (A Lógica do Lote 3 portada para cá)
app.post("/api/entregas/lote", requireManagerOrAdmin, (req, res) => {
    const { empreendimento, bloco, inicio, fim } = req.body;
    
    if (!empreendimento || !bloco || !inicio || !fim || inicio > fim) {
        return res.status(400).json({ message: "Dados inválidos para lote." });
    }

    const count = fim - inicio + 1;
    let errors = 0;
    const now = new Date().toISOString();

    db.serialize(() => {
        db.run("BEGIN TRANSACTION");
        const stmt = db.prepare(`INSERT INTO entregas (empreendimento, bloco, unidade, situacao, status_financeiro, habitavel, cvco, chaves_entregues, criado_em, atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?)`);

        for (let i = inicio; i <= fim; i++) {
            const unidadeStr = i.toString().padStart(3, '0');
            // Valores padrão para lote
            stmt.run(empreendimento, bloco, unidadeStr, "Em obra", "Pendente", "Não", "Pendente", "Não entregue", now, now, (err) => {
                if(err) errors++;
            });
        }
        stmt.finalize();
        
        db.run("COMMIT", (err) => {
            if(err || errors > 0) return res.status(500).json({ message: "Erro no processamento do lote." });
            res.status(201).json({ message: `${count} unidades criadas.` });
        });
    });
});

// --- SERVIR ARQUIVOS ESTÁTICOS ---
app.use(express.static(path.join(__dirname, "public")));

// Rotas para Single Page behavior (Redirecionar para HTMLs corretos)
app.get("/", (req, res) => res.redirect("/home.html"));

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
