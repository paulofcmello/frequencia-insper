// Site multiusuário (Vercel): cada pessoa entra com o próprio login do Aluno Online.
// O servidor não guarda senha de ninguém:
//  - cookie "sessao": os cookies da sessão do portal, criptografados (vale enquanto o portal aceitar)
//  - cookie "lembrar" (só se a pessoa marcar "Manter conectado"): login e senha criptografados,
//    guardados apenas no navegador dela, pra entrar de novo sozinho quando a sessão do portal expirar
// Os dois são HttpOnly (nenhum script da página lê) e criptografados com AES-256-GCM usando a
// variável de ambiente SEGREDO, que só existe no servidor.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { Sessao, buscarFrequencia, pagina, esc } from '../faltas-insper.mjs';

const DIA = 24 * 60 * 60;
const VALIDADE_SESSAO = 12 * 60 * 60;
const VALIDADE_LEMBRAR = 180 * DIA;

function chave() {
  if (!process.env.SEGREDO) throw new Error('Variável SEGREDO não configurada no servidor.');
  return createHash('sha256').update(process.env.SEGREDO).digest();
}

function cifrar(obj) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', chave(), iv);
  const dados = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), dados]).toString('base64url');
}

function decifrar(texto) {
  try {
    const b = Buffer.from(texto, 'base64url');
    const d = createDecipheriv('aes-256-gcm', chave(), b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'));
  } catch {
    return null;
  }
}

function lerCookies(req) {
  const out = {};
  for (const par of String(req.headers.cookie || '').split(';')) {
    const i = par.indexOf('=');
    if (i > 0) out[par.slice(0, i).trim()] = decodeURIComponent(par.slice(i + 1).trim());
  }
  return out;
}

const cookie = (nome, valor, maxAge) =>
  nome + '=' + encodeURIComponent(valor) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + maxAge;

async function lerCorpo(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return Object.fromEntries(new URLSearchParams(req.body));
  let texto = '';
  for await (const parte of req) texto += parte;
  return Object.fromEntries(new URLSearchParams(texto));
}

function responder(res, status, html, cookies = []) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (cookies.length) res.setHeader('Set-Cookie', cookies);
  res.end(html);
}

function redirecionar(res, para, cookies = []) {
  res.statusCode = 303;
  res.setHeader('Location', para);
  res.setHeader('Cache-Control', 'no-store');
  if (cookies.length) res.setHeader('Set-Cookie', cookies);
  res.end();
}

function telaLogin(erro = '') {
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Frequência — entrar</title>
<style>
  :root { --bg:#f5f5f7; --card:#fff; --txt:#1d1d1f; --sub:#6e6e73; --borda:#d2d2d7; --azul:#0a63c9; --erro:#d70015; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#000; --card:#1c1c1e; --txt:#f5f5f7; --sub:#98989d; --borda:#3a3a3c; --azul:#409cff; --erro:#ff453a; }
  }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px;
         background:var(--bg); color:var(--txt); font:15px/1.45 -apple-system,BlinkMacSystemFont,system-ui,sans-serif; }
  form { background:var(--card); border:1px solid var(--borda); border-radius:18px; padding:28px; width:100%; max-width:380px; }
  h1 { font-size:24px; margin:0 0 4px; }
  .sub { color:var(--sub); font-size:14px; margin:0 0 20px; }
  label { display:block; font-size:13px; color:var(--sub); margin:14px 0 6px; }
  input[type=text], input[type=password] { width:100%; font:inherit; padding:10px 12px; border-radius:10px;
         border:1px solid var(--borda); background:transparent; color:var(--txt); }
  .lembrar { display:flex; gap:8px; align-items:flex-start; margin-top:16px; font-size:14px; }
  .lembrar small { display:block; color:var(--sub); font-size:12px; }
  button { margin-top:20px; width:100%; font:inherit; font-weight:600; padding:11px; border:0; border-radius:980px;
           background:var(--azul); color:#fff; cursor:pointer; }
  button:disabled { opacity:.6; }
  .erro { color:var(--erro); font-size:14px; margin:12px 0 0; }
  .aviso { color:var(--sub); font-size:12px; margin:18px 0 0; }
</style>
</head>
<body>
<form method="post" action="/login" onsubmit="this.querySelector('button').disabled=true; this.querySelector('button').textContent='Entrando…'">
  <h1>Frequência</h1>
  <p class="sub">Entre com o mesmo login e senha do Aluno Online (sga.insper.edu.br).</p>
  <label for="usuario">Login</label>
  <input id="usuario" name="usuario" type="text" autocomplete="username" autocapitalize="off" spellcheck="false" required>
  <label for="senha">Senha</label>
  <input id="senha" name="senha" type="password" autocomplete="current-password" required>
  <label class="lembrar"><input type="checkbox" name="lembrar" value="1">
    <span>Manter conectado neste navegador<small>A senha fica criptografada só neste navegador, pra entrar sozinho quando a sessão do portal expirar. Use só no seu computador.</small></span>
  </label>
  ${erro ? '<p class="erro">' + esc(erro) + '</p>' : ''}
  <button type="submit">Entrar</button>
  <p class="aviso">Projeto pessoal, não oficial do Insper. A senha é usada só pra entrar no Aluno Online e não fica guardada no servidor.</p>
</form>
</body>
</html>`;
}

function mensagemDeErro(e) {
  const m = String(e.message);
  if (m.startsWith('Login recusado')) return 'Login ou senha incorretos.';
  if (m.includes('firewall')) return 'O portal do Insper bloqueou o acesso agora. Tente de novo em alguns minutos.';
  return 'Não consegui falar com o portal do Insper agora. Tente de novo em alguns minutos.';
}

async function entrar(credenciais) {
  const s = new Sessao();
  const aluno = await s.login(credenciais);
  return { s, aluno };
}

const guardarSessao = (s, aluno) =>
  cookie('sessao', cifrar({ cookies: [...s.cookies], codPessoa: aluno.codPessoa, codAluno: aluno.codAluno }), VALIDADE_SESSAO);
const apagar = (nome) => cookie(nome, '', 0);

async function mostrarPainel(res, s, aluno, cookies) {
  const { materias, fimAulas } = await buscarFrequencia(s, aluno);
  responder(res, 200, pagina({ materias, fimAulas, atualizadoEm: Date.now() }, { modo: 'web' }), cookies);
}

export default async function handler(req, res) {
  const caminho = new URL(req.url, 'http://x').pathname;
  try {
    if (req.method === 'POST' && caminho === '/login') {
      const { usuario, senha, lembrar } = await lerCorpo(req);
      if (!usuario || !senha) return responder(res, 400, telaLogin('Preencha login e senha.'));
      let entrada;
      try {
        entrada = await entrar({ usuario: String(usuario).trim(), senha: String(senha) });
      } catch (e) {
        return responder(res, 401, telaLogin(mensagemDeErro(e)));
      }
      const cookies = [guardarSessao(entrada.s, entrada.aluno)];
      cookies.push(lembrar ? cookie('lembrar', cifrar({ usuario: String(usuario).trim(), senha: String(senha) }), VALIDADE_LEMBRAR) : apagar('lembrar'));
      // Redireciona pra que o Safari ofereça salvar a senha e o F5 não reenvie o formulário
      return redirecionar(res, '/', cookies);
    }

    if (req.method === 'POST' && caminho === '/sair') {
      return redirecionar(res, '/', [apagar('sessao'), apagar('lembrar')]);
    }

    if (req.method !== 'GET' || caminho !== '/') return responder(res, 404, 'Não encontrado');

    const c = lerCookies(req);
    const sessao = c.sessao && decifrar(c.sessao);
    if (sessao) {
      const s = new Sessao();
      s.cookies = new Map(sessao.cookies);
      try {
        return await mostrarPainel(res, s, sessao, []);
      } catch {
        // Sessão do portal expirou; tenta entrar de novo com o "manter conectado"
      }
    }

    const lembrar = c.lembrar && decifrar(c.lembrar);
    if (lembrar) {
      try {
        const { s, aluno } = await entrar(lembrar);
        return await mostrarPainel(res, s, aluno, [guardarSessao(s, aluno)]);
      } catch (e) {
        const limpar = String(e.message).startsWith('Login recusado') ? [apagar('lembrar'), apagar('sessao')] : [apagar('sessao')];
        return responder(res, 200, telaLogin(mensagemDeErro(e)), limpar);
      }
    }

    return responder(res, 200, telaLogin(), c.sessao ? [apagar('sessao')] : []);
  } catch (e) {
    console.error('Erro inesperado: ' + e.message);
    return responder(res, 500, telaLogin(mensagemDeErro(e)));
  }
}
