import express, { Request, Response, NextFunction } from "express";
import session from "express-session";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

// ── Tipos ──────────────────────────────────────────────────────────────────

interface GoogleUser {
  id: string;
  email: string;
  name: string;
  picture: string;
}

// Extende a sessão do Express para guardar o usuário
declare module "express-session" {
  interface SessionData {
    user?: GoogleUser;
    oauthState?: string;
  }
}

// ── Config ─────────────────────────────────────────────────────────────────

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SESSION_SECRET = "dev_secret",
  PORT = "3000",
} = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.error("Defina GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET no .env");
  process.exit(1);
}

const REDIRECT_URI = `http://localhost:${PORT}/auth/callback`;

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo";

// ── App ────────────────────────────────────────────────────────────────────

const app = express();

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 }, // 1 hora
  })
);

// ── Middleware: protege rotas ───────────────────────────────────────────────

function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (req.session.user) {
    next();
  } else {
    res.status(401).send("Não autorizado. <a href='/auth/login'>Fazer login</a>");
  }
}

// ── Rotas de OAuth ─────────────────────────────────────────────────────────

// 1. Inicia o fluxo — redireciona o usuário para o Google
app.get("/auth/login", (req: Request, res: Response) => {
  // state evita CSRF: geramos um valor aleatório, salvamos na sessão
  // e o Google devolve junto no callback para conferirmos
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID!,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state,
    access_type: "offline", // retorna refresh_token também
    prompt: "select_account",
  });

  res.redirect(`${GOOGLE_AUTH_URL}?${params}`);
});

// 2. Callback — Google redireciona aqui com o code
app.get("/auth/callback", async (req: Request, res: Response) => {
  const { code, state, error } = req.query as Record<string, string>;

  // Usuário negou a permissão
  if (error) {
    res.status(400).send(`Erro do Google: ${error}`);
    return;
  }

  // Confere o state para prevenir CSRF
  if (!state || state !== req.session.oauthState) {
    res.status(400).send("State inválido. Possível ataque CSRF.");
    return;
  }

  if (!code) {
    res.status(400).send("Code ausente na resposta do Google.");
    return;
  }

  try {
    // 3. Troca o authorization code pelo access_token
    const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID!,
        client_secret: GOOGLE_CLIENT_SECRET!,
        redirect_uri: REDIRECT_URI,
        grant_type: "authorization_code",
      }),
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      throw new Error(`Falha ao obter token: ${err}`);
    }

    const { access_token } = (await tokenRes.json()) as { access_token: string };

    // 4. Usa o access_token para buscar os dados do usuário
    const userRes = await fetch(GOOGLE_USERINFO_URL, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    if (!userRes.ok) {
      throw new Error("Falha ao buscar dados do usuário");
    }

    const googleUser = (await userRes.json()) as {
      sub: string;
      email: string;
      name: string;
      picture: string;
    };

    // 5. Salva o usuário na sessão
    req.session.user = {
      id: googleUser.sub,
      email: googleUser.email,
      name: googleUser.name,
      picture: googleUser.picture,
    };

    delete req.session.oauthState;

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno durante autenticação.");
  }
});

// Logout — destrói a sessão
app.get("/auth/logout", (req: Request, res: Response) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ── Rotas da aplicação ─────────────────────────────────────────────────────

// Página pública
app.get("/", (_req: Request, res: Response) => {
  res.send(`
    <h1>Início</h1>
    <a href="/auth/login">Login com Google</a>
  `);
});

// Área protegida — só acessível após login
app.get("/dashboard", requireAuth, (req: Request, res: Response) => {
  const user = req.session.user!;
  res.send(`
    <h1>Dashboard</h1>
    <img src="${user.picture}" width="80" style="border-radius:50%"><br><br>
    <strong>Nome:</strong> ${user.name}<br>
    <strong>Email:</strong> ${user.email}<br>
    <strong>ID:</strong> ${user.id}<br><br>
    <a href="/auth/logout">Sair</a>
  `);
});

// ── Start ──────────────────────────────────────────────────────────────────

app.listen(Number(PORT), () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  console.log(`    Login:     http://localhost:${PORT}/auth/login`);
  console.log(`    Dashboard: http://localhost:${PORT}/dashboard`);
});
