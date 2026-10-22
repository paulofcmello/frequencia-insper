#!/usr/bin/env node
// Contador de faltas — Insper Aluno Online (Lyceum)
// Faz login com as credenciais do Keychain, busca frequência e agenda e gera frequencia.html.
//
// Credenciais (uma vez):
//   security add-generic-password -s insper-aonline -a SEU_LOGIN -w
// Uso:
//   node faltas-insper.mjs              # atualiza frequencia.html uma vez
//   node faltas-insper.mjs --abrir      # atualiza e abre no Safari
//   node faltas-insper.mjs --github     # modo GitHub Actions: gera ./site pro GitHub Pages
//   node faltas-insper.mjs --servidor   # serve a página em http://frequencia.localhost:4870 com botão de atualizar
//                                       # e atualiza sozinho depois de cada aula

import { execFileSync } from 'node:child_process';
import { publicEncrypt, constants } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ORIGEM = 'https://sga.insper.edu.br/AOnline/';
const SERVICO_KEYCHAIN = 'insper-aonline';
const PASTA = dirname(fileURLToPath(import.meta.url));
const ARQ_HTML = join(PASTA, 'frequencia.html');
const ARQ_DADOS = join(PASTA, 'frequencia-dados.json');
const PORTA = 4870;
const ENDERECO = 'http://frequencia.localhost:' + PORTA;
const MIN = 60 * 1000;
const ATRASO_POS_AULA = 30 * MIN; // dá tempo do professor lançar a chamada
const HORA_REPESCAGEM = 21; // checagem extra à noite nos dias com aula
const ESPERA_APOS_ERRO = 15 * MIN;
// Último dia de aula de cada semestre ("ano-semestre" do portal). Depois disso vêm as provas,
// que aparecem na agenda como aula mas não contam presença. Semestre sem entrada usa a agenda inteira.
const ULTIMO_DIA_DE_AULA = { '2026-62': '2026-11-25' };

// Horários que a agenda do portal mostra trocados. Cada regra diz: a aula da turma `de`
// nesse dia da semana (0 = domingo) e horário é, na verdade, da turma `para`.
const CORRECOES_DE_HORARIO = [
  { de: 'ROBCOMP_3ENGCOMA', para: 'DESCMAT_3ENGCOMA', dia: 2, hora: '16:30' }, // terça 16:30 é Desconstruindo
  { de: 'DESCMAT_3ENGCOMA', para: 'ROBCOMP_3ENGCOMA', dia: 4, hora: '16:30' }, // quinta 16:30 é Robótica
];

function corrigirTurma(turma, ev) {
  const dia = new Date(String(ev.startStr).slice(0, 10) + 'T12:00:00Z').getUTCDay();
  const hora = String(ev.startStr).slice(11, 16);
  const regra = CORRECOES_DE_HORARIO.find((r) => r.de === turma && r.dia === dia && r.hora === hora);
  return regra ? regra.para : turma;
}

function limitarAoFimDasAulas(aulas, { ano, semestre }) {
  const ultimo = ULTIMO_DIA_DE_AULA[ano + '-' + semestre];
  if (!ultimo) return aulas;
  const limite = new Date(ultimo + 'T23:59:59-03:00').getTime();
  return aulas.filter((a) => a.startDate <= limite);
}
const INTERVALO_MANUAL_MIN = 1 * MIN;

function credenciais() {
  // No GitHub Actions as credenciais vêm dos Secrets do repositório
  if (process.env.INSPER_LOGIN && process.env.INSPER_SENHA) {
    return { usuario: process.env.INSPER_LOGIN, senha: process.env.INSPER_SENHA };
  }
  const security = (...args) =>
    execFileSync('/usr/bin/security', ['find-generic-password', '-s', SERVICO_KEYCHAIN, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  let usuario, senha;
  try {
    usuario = (security().match(/"acct"<blob>="([^"]*)"/) || [])[1];
    senha = security('-w').replace(/\n$/, '');
  } catch {
    throw new Error(
      'Login do Insper não encontrado no Keychain. Rode: security add-generic-password -s ' +
        SERVICO_KEYCHAIN + ' -a SEU_LOGIN -w'
    );
  }
  if (!usuario || !senha) throw new Error('Item "' + SERVICO_KEYCHAIN + '" no Keychain está incompleto.');
  return { usuario, senha };
}

class Sessao {
  cookies = new Map();

  guardarCookies(res) {
    for (const c of res.headers.getSetCookie?.() || []) {
      const [par] = c.split(';');
      const i = par.indexOf('=');
      this.cookies.set(par.slice(0, i).trim(), par.slice(i + 1).trim());
    }
  }

  async req(caminho, opcoes = {}) {
    const res = await fetch(ORIGEM + caminho, {
      ...opcoes,
      // Mesmos cabeçalhos de um Safari no portal; o firewall do Insper barra o login de clientes "não navegador"
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15',
        Accept: 'application/json, text/plain, */*',
        'Accept-Language': 'pt-BR,pt;q=0.9',
        Origin: 'https://sga.insper.edu.br',
        Referer: ORIGEM,
        ...opcoes.headers,
        Cookie: [...this.cookies].map(([k, v]) => k + '=' + v).join('; '),
      },
      redirect: 'manual',
    });
    this.guardarCookies(res);
    return res;
  }

  async json(caminho) {
    const res = await this.req(caminho);
    if (!res.ok) throw new Error('HTTP ' + res.status + ' em ' + caminho);
    return res.json();
  }

  async login({ usuario, senha }) {
    await this.req('');
    const chave = (await (await this.req('config-properties/public-key')).text()).trim();
    // A chave vem numa linha só; o PEM precisa de quebras a cada 64 caracteres
    const corpo = chave.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const pem = '-----BEGIN PUBLIC KEY-----\n' + corpo.match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----\n';
    // Mesmo formato do JSEncrypt usado pelo portal: RSA PKCS#1 v1.5 em base64
    const senhaCifrada = publicEncrypt({ key: pem, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(senha)).toString('base64');

    const res = await this.req('auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: usuario, password: senhaCifrada, recaptchaResponse: '' }).toString(),
    });
    if (!res.ok) {
      const msg = (await res.text().catch(() => '')).slice(0, 200);
      // 403 com "Access Denied" é o firewall do site, não senha errada; só senha errada pausa as tentativas
      if (/Access Denied/i.test(msg)) throw new Error('Acesso bloqueado pelo firewall do Insper (HTTP ' + res.status + ')');
      throw new Error('Login recusado (HTTP ' + res.status + ')' + (msg ? ': ' + msg : ''));
    }
    const userData = this.cookies.get('user-data');
    if (!userData) throw new Error('Login sem cookie de sessão; o portal pode ter mudado.');
    const user = JSON.parse(Buffer.from(decodeURIComponent(userData), 'base64').toString('utf8'));
    const aluno = (await this.json('apix/api/rest/alunos/user/' + user.id)).content?.[0];
    if (!aluno?.codAluno) throw new Error('Não achei o código de aluno.');
    return { codPessoa: aluno.id, codAluno: aluno.codAluno, nome: aluno.nomeAluno };
  }
}

async function buscarFrequencia(s, { codPessoa, codAluno }) {
  const resumo = await s.json(
    'apix/api/rest/alunos/codAluno/' + codAluno + '/codPessoa/' + codPessoa + '/Frequencias?page=0&size=1000'
  );

  // A agenda lista cada aula do semestre (feriados já excluídos), um mês por consulta
  const hoje = new Date();
  const isoDia = (dt) =>
    dt.getFullYear() + '-' + String(dt.getMonth() + 1).padStart(2, '0') + '-' + String(dt.getDate()).padStart(2, '0');
  const meses = [];
  for (let i = -6; i <= 6; i++) meses.push(new Date(hoje.getFullYear(), hoje.getMonth() + i, 1));
  const eventos = (
    await Promise.all(
      meses.map((ini) => {
        const fim = new Date(ini.getFullYear(), ini.getMonth() + 1, 1);
        return s
          .json(
            'apix/api/rest/alunos/pessoa/' + codPessoa + '/events?codAluno=' + codAluno +
              '&start=' + isoDia(ini) + 'T00:00:00.000-03:00&end=' + isoDia(fim) + 'T00:00:00.000-03:00' +
              '&page=0&size=2000&timezone=false'
          )
          .then((j) => j.content || j || [], () => []);
      })
    )
  ).flat();
  const aulasPorTurma = {};
  const vistos = new Set();
  for (const ev of eventos) {
    if (ev.tipoEvento !== 'AULA' || vistos.has(ev.eventId)) continue;
    vistos.add(ev.eventId);
    const turma = corrigirTurma((String(ev.descricao).match(/Turma: (\S+)/) || [])[1], ev);
    if (turma) (aulasPorTurma[turma] ||= []).push(ev);
  }

  // Atividades complementares (AC, ex.: ligas e organizações estudantis) não têm controle de falta
  const disciplinas = (resumo.content || []).filter(
    (m) => !/^AC\s*-/i.test(m.componenteCurricular.trim()) && !/^GRAD_AC_/i.test(m.codDisciplina)
  );

  const materias = await Promise.all(
    disciplinas.map(async (m) => {
      const d = await s.json(
        'apix/v2/alunos/' + codAluno + '/detalhes-faltas?ano=' + m.ano + '&semestre=' + m.semestre +
          '&codDisciplina=' + encodeURIComponent(m.codDisciplina) + '&codTurma=' + encodeURIComponent(m.codigoTurma)
      );
      const nivel = (d.detalhesFrequenciaPorNivel || [])[0] || {};
      const datas = (d.faltasDiarias || []).map((f) => f.data);
      const faltas = nivel.faltasAcumuladas ?? d.totalFaltas ?? datas.length;

      const aulas = limitarAoFimDasAulas(aulasPorTurma[m.codigoTurma] || [], m);
      // O portal conta aulas e faltas permitidas em horas; cada encontro vale a duração dele (2h)
      const horasPorAula = aulas.length ? Math.round((aulas[0].endDate - aulas[0].startDate) / 3600000) || 1 : 2;
      const previstasPortal = nivel.aulasPrevistas ?? m.aulasPrevistas;
      const permitidas = Math.floor((nivel.faltasPermitidas ?? previstasPortal * 0.25) / horasPorAula);

      const total = aulas.length || Math.round(previstasPortal / horasPorAula);
      const dadas = aulas.length
        ? aulas.filter((a) => a.endDate <= hoje.getTime()).length
        : Math.round((nivel.aulasMinistradas ?? m.cargaHoraria) / horasPorAula);
      const proxima = aulas.map((a) => a.startDate).filter((t) => t > hoje.getTime()).sort((a, b) => a - b)[0];
      return {
        nome: m.componenteCurricular.trim(),
        faltas,
        permitidas,
        restantes: permitidas - faltas,
        presencas: dadas - faltas,
        presencasNecessarias: total - permitidas,
        aulasRestantes: total - dadas,
        dadas,
        total,
        ultimaAula: aulas.length ? Math.max(...aulas.map((a) => a.startDate)) : null,
        proximaAula: proxima ?? null,
        datas,
      };
    })
  );
  materias.sort((a, b) => folga(a) - folga(b) || a.restantes - b.restantes);
  const fimAulas = disciplinas
    .flatMap((m) => limitarAoFimDasAulas(aulasPorTurma[m.codigoTurma] || [], m).map((a) => a.endDate))
    .sort((a, b) => a - b);
  return { materias, fimAulas };
}

// Fração das aulas restantes em que ainda dá pra faltar: 0 = não pode mais, 1 = pode faltar em todas.
// Negativo quando já passou do limite. Define a ordem dos cartões e a cor.
function folga(m) {
  if (m.restantes < 0) return -1;
  if (m.aulasRestantes <= 0) return 1;
  return Math.min(m.restantes, m.aulasRestantes) / m.aulasRestantes;
}

// Momentos em que vale a pena atualizar: 30 min depois de cada aula
// e uma repescagem às 21h de cada dia que teve aula. Fim de semana e feriado não têm aula, então não entram.
function checkpoints(fimAulas = []) {
  const pontos = new Set();
  for (const fim of fimAulas) {
    pontos.add(fim + ATRASO_POS_AULA);
    const noite = new Date(fim);
    noite.setHours(HORA_REPESCAGEM, 0, 0, 0);
    if (noite.getTime() > fim + ATRASO_POS_AULA) pontos.add(noite.getTime());
  }
  return [...pontos].sort((a, b) => a - b);
}

function precisaAtualizar(dados, agora = Date.now()) {
  if (!dados?.atualizadoEm) return true;
  // Sem aulas conhecidas (fim do semestre): uma vez por dia, pra pegar o calendário novo
  if (!dados.fimAulas?.some((f) => f > agora - 24 * 60 * MIN)) return agora - dados.atualizadoEm > 24 * 60 * MIN;
  return checkpoints(dados.fimAulas).some((t) => t > dados.atualizadoEm && t <= agora);
}

function proximaAtualizacao(dados, agora = Date.now()) {
  return checkpoints(dados?.fimAulas).find((t) => t > agora) ?? null;
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const dataBR = (t, opc) => new Date(t).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', ...opc });

function cartao(m) {
  const podeFaltar = Math.max(0, Math.min(m.restantes, m.aulasRestantes));
  const pct = m.aulasRestantes > 0 ? Math.round((podeFaltar / m.aulasRestantes) * 100) : 0;
  const f = folga(m);
  const nivel = m.restantes <= 0 || f < 0.25 ? 'ruim' : f < 0.5 ? 'medio' : 'bom';
  const notaFaltas = m.restantes < 0
    ? 'passou ' + -m.restantes + ' do limite'
    : m.restantes === 0
      ? 'não pode mais faltar'
      : 'pode faltar <b>' + podeFaltar + '/' + m.aulasRestantes + '</b> restantes (' + pct + '%)';
  const faltamPresencas = Math.max(0, m.presencasNecessarias - m.presencas);
  const notaPresencas = faltamPresencas === 0
    ? 'presença garantida'
    : 'faltam <b>' + faltamPresencas + '</b> de ' + m.aulasRestantes + ' aulas';
  const barra = (v, t) => (t > 0 ? Math.min(100, Math.max(0, (v / t) * 100)) : 0).toFixed(1);
  const ultimas = m.datas.slice(-3).join(', ');

  return `
  <article class="card ${nivel}">
    <header>
      <h2>${esc(m.nome)}</h2>
      <div class="restam"><span class="num">${m.aulasRestantes}</span> aulas restantes</div>
    </header>
    <div class="linha">
      <div class="rotulo"><span>Presenças <b>${m.presencas}/${m.presencasNecessarias}</b></span><span class="nota pres">${notaPresencas}</span></div>
      <div class="trilho"><div class="barra pres" style="width:${barra(m.presencas, m.presencasNecessarias)}%"></div></div>
    </div>
    <div class="linha">
      <div class="rotulo"><span>Faltas <b>${m.faltas}/${m.permitidas}</b></span><span class="nota falt">${notaFaltas}</span></div>
      <div class="trilho"><div class="barra falt" style="width:${barra(m.faltas, m.permitidas)}%"></div></div>
    </div>
    <footer>
      Aulas dadas: ${m.dadas} de ${m.total}${m.ultimaAula ? ' · última aula ' + dataBR(m.ultimaAula, { day: '2-digit', month: '2-digit' }) : ''}
      ${m.proximaAula ? '<br>Próxima: ' + esc(dataBR(m.proximaAula, { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })) : ''}
      ${ultimas ? '<br>Últimas faltas: ' + esc(ultimas) : ''}
    </footer>
  </article>`;
}

// Botão do servidor local: chama /atualizar no próprio Mac
const scriptBotaoLocal = `
    b.onclick = async () => {
      b.disabled = true; b.textContent = 'Atualizando…';
      try {
        const r = await fetch('/atualizar', { method: 'POST' });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) alert(j.erro || 'Não consegui atualizar.');
      } finally { location.reload(); }
    };`;

// Botão do GitHub Pages: dispara o workflow pela API usando um token guardado só neste navegador,
// acompanha a execução e recarrega quando a página nova estiver publicada.
const scriptBotaoGithub = (repo) => `
    const REPO = ${JSON.stringify(repo)}, WORKFLOW = 'atualizar.yml', CHAVE = 'frequencia-gh-token';
    const api = (caminho, opcoes = {}) => fetch('https://api.github.com/repos/' + REPO + caminho, {
      ...opcoes,
      headers: { Accept: 'application/vnd.github+json', Authorization: 'Bearer ' + localStorage.getItem(CHAVE), ...(opcoes.headers || {}) },
    });
    const esperar = (ms) => new Promise((r) => setTimeout(r, ms));
    const atualizadoAntes = document.body.dataset.atualizado;
    b.onclick = async () => {
      if (!localStorage.getItem(CHAVE)) {
        const t = prompt('Cole o token do GitHub (só precisa uma vez neste navegador):');
        if (!t) return;
        localStorage.setItem(CHAVE, t.trim());
      }
      b.disabled = true; b.textContent = 'Pedindo atualização…';
      const inicio = new Date(Date.now() - 60 * 1000).toISOString();
      try {
        const r = await api('/actions/workflows/' + WORKFLOW + '/dispatches', {
          method: 'POST', body: JSON.stringify({ ref: 'main', inputs: { forcar: true } }),
        });
        if (r.status === 401 || r.status === 403 || r.status === 404) {
          localStorage.removeItem(CHAVE);
          throw new Error('O token não foi aceito (HTTP ' + r.status + '). Clique de novo e cole um token válido.');
        }
        if (!r.ok) throw new Error('GitHub respondeu HTTP ' + r.status);
        const limite = Date.now() + 6 * 60 * 1000;
        let execucao = null;
        while (Date.now() < limite) {
          await esperar(5000);
          const j = await (await api('/actions/workflows/' + WORKFLOW + '/runs?event=workflow_dispatch&per_page=1&created=%3E%3D' + inicio)).json();
          execucao = (j.workflow_runs || [])[0];
          if (!execucao) continue;
          if (execucao.status !== 'completed') { b.textContent = 'Atualizando…'; continue; }
          if (execucao.conclusion !== 'success') throw new Error('A atualização falhou no GitHub (' + execucao.conclusion + ').');
          b.textContent = 'Publicando…';
          const d = await (await fetch('dados.json?t=' + Date.now(), { cache: 'no-store' })).json().catch(() => ({}));
          if (String(d.atualizadoEm) !== atualizadoAntes) return location.reload();
        }
        throw new Error('Demorou demais. Tente recarregar a página daqui a pouco.');
      } catch (e) {
        alert(e.message);
        b.disabled = false; b.textContent = 'Atualizar agora';
      }
    };`;

function pagina({ materias, atualizadoEm, erro, fimAulas }, { modo = 'arquivo', repo } = {}) {
  const aviso = erro
    ? `<div class="aviso">Não consegui atualizar agora (${esc(erro)}). Mostrando os dados de ${esc(dataBR(atualizadoEm))}.</div>`
    : '';
  const proxima = modo === 'servidor' || modo === 'github' ? proximaAtualizacao({ fimAulas }) : null;
  const quandoProxima = proxima
    ? ' · próxima automática ' + dataBR(proxima, { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
    : '';
  // Site multiusuário (Vercel): os dados já vêm atualizados a cada visita
  const botaoWeb = `<form class="acoes" method="post" action="/sair">
      <a id="atualizar" href="/">Atualizar</a>
      <button type="submit" class="sair">Sair</button>
    </form>`;
  const botao = modo === 'web'
    ? botaoWeb
    : modo !== 'arquivo'
    ? `<button id="atualizar" type="button">Atualizar agora</button>
  <script>
    const b = document.getElementById('atualizar');
    ${modo === 'github' ? scriptBotaoGithub(repo) : scriptBotaoLocal}
    // Recarrega a página a cada 5 min pra mostrar atualizações automáticas
    setTimeout(() => { if (!b.disabled) location.reload(); }, 5 * 60 * 1000);
  </script>`
    : '';
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${modo === 'arquivo' ? '<meta http-equiv="refresh" content="300">' : ''}
<title>Frequência Insper</title>
<style>
  :root { --bg:#f5f5f7; --card:#fff; --txt:#1d1d1f; --sub:#6e6e73; --trilho:#e5e5ea;
          --bom:#248a3d; --medio:#c93400; --ruim:#d70015; --pres:#0a63c9; --borda:#e5e5ea; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#000; --card:#1c1c1e; --txt:#f5f5f7; --sub:#98989d; --trilho:#3a3a3c;
            --bom:#30d158; --medio:#ff9f0a; --ruim:#ff453a; --pres:#409cff; --borda:#2c2c2e; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt); font:15px/1.45 -apple-system,BlinkMacSystemFont,system-ui,sans-serif; }
  main { max-width:1100px; margin:0 auto; padding:32px 16px 48px; }
  h1 { font-size:28px; margin:0 0 4px; }
  .sub { color:var(--sub); margin:0 0 24px; font-size:14px; }
  .grade { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; }
  .card { background:var(--card); border:1px solid var(--borda); border-radius:16px; padding:18px 18px 14px; border-top:4px solid var(--bom); }
  .card.medio { border-top-color:var(--medio); } .card.ruim { border-top-color:var(--ruim); }
  header { display:flex; justify-content:space-between; gap:12px; align-items:flex-start; margin-bottom:6px; }
  h2 { font-size:15px; margin:0; letter-spacing:.2px; }
  .restam { text-align:right; color:var(--sub); font-size:12px; white-space:nowrap; line-height:1.1; }
  .restam .num { display:block; font-size:26px; font-weight:700; color:var(--txt); }
  .linha { margin-top:12px; }
  .rotulo { display:flex; justify-content:space-between; gap:8px; font-size:14px; flex-wrap:wrap; }
  .nota.pres { color:var(--pres); }
  .card.bom .nota.falt { color:var(--bom); } .card.medio .nota.falt { color:var(--medio); } .card.ruim .nota.falt { color:var(--ruim); }
  .trilho { height:8px; background:var(--trilho); border-radius:4px; margin-top:6px; overflow:hidden; }
  .barra { height:100%; border-radius:4px; }
  .barra.pres { background:var(--pres); }
  .card.bom .barra.falt { background:var(--bom); } .card.medio .barra.falt { background:var(--medio); } .card.ruim .barra.falt { background:var(--ruim); }
  footer { margin-top:14px; padding-top:10px; border-top:1px solid var(--borda); color:var(--sub); font-size:12.5px; }
  .aviso { background:#fff4e5; color:#8a4b00; border:1px solid #ffd8a8; padding:10px 14px; border-radius:10px; margin-bottom:20px; font-size:14px; }
  @media (prefers-color-scheme: dark) { .aviso { background:#3a2a10; color:#ffcf8a; border-color:#5c4214; } }
  .topo { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; }
  #atualizar { font:inherit; font-size:14px; font-weight:600; padding:8px 16px; border-radius:980px; border:0;
               background:var(--pres); color:#fff; cursor:pointer; }
  #atualizar:disabled { opacity:.6; cursor:default; }
  a#atualizar { text-decoration:none; display:inline-block; }
  .acoes { display:flex; gap:8px; align-items:center; margin:0; }
  .sair { font:inherit; font-size:14px; padding:8px 14px; border-radius:980px; border:1px solid var(--borda);
          background:transparent; color:var(--sub); cursor:pointer; }
  .rodape { color:var(--sub); font-size:12px; margin-top:28px; }
</style>
</head>
<body data-atualizado="${esc(atualizadoEm)}">
<main>
  <div class="topo">
    <h1>Frequência</h1>
    ${botao}
  </div>
  <p class="sub">Atualizado em ${esc(dataBR(atualizadoEm))}${esc(quandoProxima)} · ordenado pela % das aulas restantes que você ainda pode faltar, da menor pra maior</p>
  ${aviso}
  <section class="grade">${materias.map(cartao).join('')}</section>
  ${modo === 'web' ? '<p class="rodape">Projeto pessoal, não oficial do Insper. Os dados vêm do Aluno Online com o seu login.</p>' : ''}
</main>
</body>
</html>
`;
}

function salvar(caminho, conteudo) {
  writeFileSync(caminho + '.tmp', conteudo);
  renameSync(caminho + '.tmp', caminho);
}

function lerDados() {
  try {
    return JSON.parse(readFileSync(ARQ_DADOS, 'utf8'));
  } catch {
    return null;
  }
}

// Atualiza e salva. Em caso de erro, mantém os últimos dados bons e registra o erro neles.
async function atualizar(motivo) {
  const hora = () => new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
  try {
    const s = new Sessao();
    const aluno = await s.login(credenciais());
    const { materias, fimAulas } = await buscarFrequencia(s, aluno);
    const dados = { materias, fimAulas, atualizadoEm: Date.now() };
    salvar(ARQ_DADOS, JSON.stringify(dados, null, 2));
    salvar(ARQ_HTML, pagina(dados));
    console.log(hora() + ' · ' + motivo + ' · atualizado: ' + materias.length + ' matérias');
    return dados;
  } catch (e) {
    console.error(hora() + ' · ' + motivo + ' · erro: ' + e.message);
    const anteriores = lerDados();
    if (anteriores) {
      const dados = { ...anteriores, erro: e.message, ultimaFalha: Date.now() };
      salvar(ARQ_DADOS, JSON.stringify(dados, null, 2));
      salvar(ARQ_HTML, pagina(dados));
    }
    throw e;
  }
}

function servidor() {
  let emAndamento = null;
  const rodar = (motivo) => (emAndamento ||= atualizar(motivo).finally(() => (emAndamento = null)));

  // Checa a cada 5 min se alguma aula terminou desde a última atualização. Não acessa a rede;
  // só faz login quando passou um checkpoint. Funciona mesmo se o Mac dormiu no meio.
  const checar = () => {
    const dados = lerDados();
    const agora = Date.now();
    // Senha recusada: não insiste sozinho, pra não bloquear a conta. Volta a tentar após um clique em "Atualizar agora".
    if (dados?.erro?.startsWith('Login recusado')) return;
    if (dados?.ultimaFalha && agora - dados.ultimaFalha < ESPERA_APOS_ERRO) return;
    if (precisaAtualizar(dados, agora)) rodar('automática').catch(() => {});
  };
  checar();
  setInterval(checar, 5 * MIN);

  const origensOk = new Set(
    [ENDERECO, 'http://localhost:' + PORTA, 'http://127.0.0.1:' + PORTA, 'http://[::1]:' + PORTA]
  );
  const app = async (req, res) => {
    const responder = (status, tipo, corpo) => {
      res.writeHead(status, { 'Content-Type': tipo + '; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(corpo);
    };
    if (req.method === 'GET' && req.url === '/') {
      const dados = lerDados();
      if (!dados) return responder(200, 'text/html', '<p style="font-family:system-ui">Buscando dados… recarregue em alguns segundos.</p>');
      return responder(200, 'text/html', pagina(dados, { modo: 'servidor' }));
    }
    if (req.method === 'POST' && req.url === '/atualizar') {
      // Só aceita cliques vindos da própria página, não de outros sites abertos no navegador
      if (!origensOk.has(req.headers.origin)) return responder(403, 'application/json', '{"erro":"origem não permitida"}');
      const dados = lerDados();
      if (dados?.atualizadoEm && Date.now() - dados.atualizadoEm < INTERVALO_MANUAL_MIN && !dados.erro) {
        return responder(200, 'application/json', '{"ok":true}');
      }
      try {
        await rodar('manual');
        return responder(200, 'application/json', '{"ok":true}');
      } catch (e) {
        return responder(502, 'application/json', JSON.stringify({ erro: e.message }));
      }
    }
    responder(404, 'text/plain', 'não encontrado');
  };
  // *.localhost resolve pra IPv4 e IPv6 locais; escuta nos dois pra o Safari não esperar o fallback
  createServer(app).listen(PORTA, '127.0.0.1', () => console.log('Servindo em ' + ENDERECO));
  createServer(app).listen(PORTA, '::1').on('error', () => {});
}

// Modo GitHub Actions: lê os dados publicados da última vez no GitHub Pages, decide se precisa
// atualizar e grava o site novo em ./site. Sinaliza pro workflow se deve publicar.
async function github() {
  const saida = join(process.cwd(), 'site');
  const forcar = process.env.FORCAR === 'true';
  const sinalizar = (publicar) => {
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, 'publicar=' + publicar + '\n');
  };
  const escrever = (dados) => {
    mkdirSync(saida, { recursive: true });
    writeFileSync(join(saida, 'dados.json'), JSON.stringify(dados, null, 2));
    writeFileSync(join(saida, 'index.html'), pagina(dados, { modo: 'github', repo: process.env.GITHUB_REPOSITORY }));
    sinalizar(true);
  };

  let anteriores = null;
  if (process.env.PAGES_URL) {
    try {
      const r = await fetch(process.env.PAGES_URL.replace(/\/?$/, '/') + 'dados.json?t=' + Date.now());
      if (r.ok) anteriores = await r.json();
    } catch {}
  }

  if (!forcar && anteriores) {
    const agora = Date.now();
    const pausado =
      anteriores.erro?.startsWith('Login recusado') ||
      (anteriores.ultimaFalha && agora - anteriores.ultimaFalha < ESPERA_APOS_ERRO);
    if (pausado || !precisaAtualizar(anteriores, agora)) {
      console.log('Nada a fazer agora. Próxima: ' + (proximaAtualizacao(anteriores) ? dataBR(proximaAtualizacao(anteriores)) : '—'));
      return sinalizar(false);
    }
  }

  try {
    const s = new Sessao();
    const aluno = await s.login(credenciais());
    const { materias, fimAulas } = await buscarFrequencia(s, aluno);
    escrever({ materias, fimAulas, atualizadoEm: Date.now() });
    console.log('Atualizado: ' + materias.length + ' matérias');
  } catch (e) {
    console.error('Erro: ' + e.message);
    if (anteriores) escrever({ ...anteriores, erro: e.message, ultimaFalha: Date.now() });
    else sinalizar(false);
    process.exitCode = 1;
  }
}

async function main() {
  if (process.argv.includes('--github')) return github();
  if (process.argv.includes('--servidor')) return servidor();
  try {
    await atualizar('manual');
    console.log('Página: ' + ARQ_HTML);
  } catch {
    process.exitCode = 1;
  }
  if (process.argv.includes('--abrir')) execFileSync('/usr/bin/open', ['-a', 'Safari', ARQ_HTML]);
}

// Usado pelo site multiusuário (api/index.mjs)
export { Sessao, buscarFrequencia, pagina, esc };

// Só roda a linha de comando quando o arquivo é executado direto, não quando é importado
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
