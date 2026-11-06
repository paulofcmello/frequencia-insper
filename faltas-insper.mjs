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
  const feriados = {}; // 'AAAA-MM-DD' → nome; recesso de vários dias vira um dia por entrada
  for (const ev of eventos) {
    if (ev.tipoEvento === 'FERIADO' || ev.tipoEvento === 'RECESSO') {
      const nome = String(ev.descricao || ev.title).replace(/^Evento:\s*/, '');
      const fim = String(ev.endStr || ev.startStr).slice(0, 10);
      for (let d = new Date(String(ev.startStr).slice(0, 10) + 'T12:00:00Z'); d.toISOString().slice(0, 10) <= fim; d.setUTCDate(d.getUTCDate() + 1)) {
        feriados[d.toISOString().slice(0, 10)] ||= nome;
      }
    }
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
      const diasAula = aulas.map((a) => String(a.startStr).slice(0, 16)).sort();
      // Só os feriados que caem num dia da semana em que a matéria tem aula, dentro do semestre dela
      const semana = new Set(diasAula.map((d) => new Date(d.slice(0, 10) + 'T12:00:00Z').getUTCDay()));
      const feriadosDaMateria = Object.entries(feriados)
        .filter(([d]) => diasAula.length && d >= diasAula[0] && d <= diasAula.at(-1) && semana.has(new Date(d + 'T12:00:00Z').getUTCDay()))
        .map(([dia, nome]) => ({ dia, nome }));
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
        diasAula,
        feriados: feriadosDaMateria,
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

// Calendário dos meses com aula: aula futura, presença, falta, feriado e hoje
function calendario(m) {
  if (!m.diasAula?.length) return '<p class="cal-vazio">Sem agenda de aulas no portal.</p>';
  const hoje = new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' });
  const aulas = {};
  for (const d of m.diasAula) (aulas[d.slice(0, 10)] ||= []).push(d.slice(11, 16));
  const faltas = new Set(m.datas.map((d) => d.split('/').reverse().join('-'))); // portal manda DD/MM/AAAA
  const feriados = Object.fromEntries((m.feriados || []).map((f) => [f.dia, f.nome]));
  const meses = [];
  for (let d = new Date(m.diasAula[0].slice(0, 7) + '-01T12:00:00Z'); d.toISOString().slice(0, 7) <= m.diasAula.at(-1).slice(0, 7); d.setUTCMonth(d.getUTCMonth() + 1)) {
    const ano = d.getUTCFullYear(), mes = d.getUTCMonth();
    const nDias = new Date(Date.UTC(ano, mes + 1, 0)).getUTCDate();
    let dias = '<i></i>'.repeat(d.getUTCDay());
    for (let i = 1; i <= nDias; i++) {
      const iso = ano + '-' + String(mes + 1).padStart(2, '0') + '-' + String(i).padStart(2, '0');
      const tipo = faltas.has(iso) ? 'falta' : feriados[iso] ? 'feriado' : aulas[iso] ? (iso < hoje ? 'foi' : 'aula') : '';
      const dica = faltas.has(iso) ? 'Falta' : feriados[iso] ? 'Feriado: ' + feriados[iso] : aulas[iso] ? 'Aula ' + aulas[iso].join(', ') : '';
      dias += `<span class="${tipo}${iso === hoje ? ' hoje' : ''}"${dica ? ` title="${esc(dica)}"` : ''}>${i}</span>`;
    }
    const nome = new Date(Date.UTC(ano, mes, 15)).toLocaleDateString('pt-BR', { month: 'long', timeZone: 'UTC' });
    meses.push(`<div class="mes"${d.toISOString().slice(0, 7) === hoje.slice(0, 7) ? '' : ' hidden'}><div class="mes-nome">${nome}</div><div class="dias"><b>D</b><b>S</b><b>T</b><b>Q</b><b>Q</b><b>S</b><b>S</b>${dias}</div></div>`);
  }
  const listaFeriados = (m.feriados || [])
    .map((f) => f.dia.split('-').reverse().slice(0, 2).join('/') + ' ' + esc(f.nome))
    .join(' · ');
  // Mostra só o mês atual (ou o mais próximo do semestre); as setas trocam
  let atual = meses.findIndex((x) => !x.includes(' hidden>'));
  if (atual < 0) atual = hoje < m.diasAula[0] ? 0 : meses.length - 1;
  meses[atual] = meses[atual].replace(' hidden>', '>');
  return `${meses.join('')}
    <div class="nav-mes"><button type="button" aria-label="Mês anterior" onclick="trocarMes(this,-1)"${atual === 0 ? ' disabled' : ''}>${SETA_ESQ}</button><button type="button" aria-label="Próximo mês" onclick="trocarMes(this,1)"${atual === meses.length - 1 ? ' disabled' : ''}>${SETA_DIR}</button></div>
    <div class="legenda"><span class="aula">aula</span><span class="foi">presença</span><span class="falta">falta</span><span class="feriado">feriado</span><span class="hoje">hoje</span></div>
    ${listaFeriados ? '<div class="cal-feriados">Feriados sem aula: ' + listaFeriados + '</div>' : ''}`;
}

// Portal manda nomes em caixa alta; deixa legível sem estragar algarismos romanos
const MINUSCULAS = new Set(['a', 'o', 'e', 'de', 'da', 'do', 'das', 'dos', 'em', 'na', 'no', 'para', 'com']);
const nomeBonito = (s) => String(s).toLowerCase().split(' ')
  .map((p, i) => /^[ivx]+$/.test(p) ? p.toUpperCase() : i && MINUSCULAS.has(p) ? p : p.charAt(0).toUpperCase() + p.slice(1))
  .join(' ');

const seta = (d) => `<svg class="seta" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="${d}" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const SETA_BAIXO = seta('M4 6l4 4 4-4'), SETA_ESQ = seta('M10 4L6 8l4 4'), SETA_DIR = seta('M6 4l4 4-4 4');

function cartao(m) {
  const podeFaltar = Math.max(0, Math.min(m.restantes, m.aulasRestantes));
  const pct = m.aulasRestantes > 0 ? Math.round((podeFaltar / m.aulasRestantes) * 100) : 0;
  const f = folga(m);
  const nivel = m.restantes <= 0 || f < 0.25 ? 'ruim' : f < 0.5 ? 'medio' : 'bom';
  const plural = (n, um, varios) => n + ' ' + (n === 1 ? um : varios);
  const heroTitulo = m.restantes < 0
    ? 'passou ' + -m.restantes + ' do limite'
    : m.restantes === 0 ? 'não pode mais faltar' : m.aulasRestantes > 0 ? 'pode faltar' : 'aulas encerradas';
  const heroSub = m.aulasRestantes > 0
    ? 'de ' + plural(m.aulasRestantes, 'aula restante', 'aulas restantes') + (m.restantes > 0 ? ' · ' + pct + '%' : '')
    : 'sem aulas restantes';
  // Um bloco por aula restante: cheios são as que ainda dá pra faltar
  const blocos = Array.from({ length: m.aulasRestantes }, (_, i) => `<i${i < podeFaltar ? ' class="livre"' : ''}></i>`).join('');
  const faltamPresencas = Math.max(0, m.presencasNecessarias - m.presencas);
  const notaPresencas = faltamPresencas === 0 ? 'presença garantida' : 'faltam ' + faltamPresencas + ' de ' + m.aulasRestantes;
  const barra = (v, t) => (t > 0 ? Math.min(100, Math.max(0, (v / t) * 100)) : 0).toFixed(1);
  const ultimas = m.datas.slice(-3).map((d) => d.slice(0, 5)).join(', '); // DD/MM/AAAA → DD/MM
  const curta = (t, opc) => esc(dataBR(t, opc).replace('.', ''));

  return `
  <details class="card ${nivel}">
    <summary>
    <h2>${esc(nomeBonito(m.nome))}</h2>
    <div class="hero">
      <span class="big">${podeFaltar}</span>
      <div class="hero-txt"><b>${heroTitulo}</b><span>${heroSub}</span></div>
    </div>
    ${blocos ? `<div class="blocos" role="img" aria-label="${podeFaltar} de ${m.aulasRestantes} aulas restantes ainda podem ser faltadas">${blocos}</div>` : ''}
    <div class="stats">
      <div>
        <div class="k">Presenças</div>
        <div class="v">${m.presencas}<small>/${m.presencasNecessarias}</small></div>
        <div class="trilho"><div class="barra pres" style="width:${barra(m.presencas, m.presencasNecessarias)}%"></div></div>
        <div class="nota">${notaPresencas}</div>
      </div>
      <div>
        <div class="k">Faltas</div>
        <div class="v">${m.faltas}<small>/${m.permitidas}</small></div>
        <div class="trilho"><div class="barra falt" style="width:${barra(m.faltas, m.permitidas)}%"></div></div>
        <div class="nota">${ultimas ? 'últimas ' + esc(ultimas) : 'nenhuma falta'}</div>
      </div>
    </div>
    <footer>
      <div>
        ${m.proximaAula ? '<div class="prox">Próxima <b>' + curta(m.proximaAula, { weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) + '</b></div>' : ''}
        <div>${m.dadas}/${m.total} aulas dadas${m.ultimaAula ? ' · última ' + curta(m.ultimaAula, { day: '2-digit', month: '2-digit' }) : ''}</div>
      </div>
      <span class="ver-cal">Calendário ${SETA_BAIXO}</span>
    </footer>
    </summary>
    <div class="cal">${calendario(m)}</div>
  </details>`;
}

// Botão do servidor local: chama /atualizar no próprio Mac
const scriptBotaoLocal = `
    b.onclick = async () => {
      b.disabled = true; b.textContent = 'Atualizando…';
      try {
        const r = await fetch('/atualizar', { method: 'POST' });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) alert(j.erro || 'Não consegui atualizar.');
      } finally { await recarregar().catch(() => location.reload()); b.disabled = false; b.textContent = 'Atualizar agora'; }
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
    b.onclick = async () => {
      if (!localStorage.getItem(CHAVE)) {
        const t = prompt('Cole o token do GitHub (só precisa uma vez neste navegador):');
        if (!t) return;
        localStorage.setItem(CHAVE, t.trim());
      }
      b.disabled = true; b.textContent = 'Pedindo atualização…';
      const atualizadoAntes = document.body.dataset.atualizado;
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
          if (String(d.atualizadoEm) !== atualizadoAntes) {
            // ?t= fura o cache do GitHub Pages, que ainda pode ter a página velha
            await recarregar(location.pathname + '?t=' + Date.now());
            b.disabled = false; b.textContent = 'Atualizar agora';
            return;
          }
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
    // Busca a página de novo a cada 5 min pra mostrar atualizações automáticas
    setInterval(() => { if (!b.disabled) recarregar().catch(() => {}); }, 5 * 60 * 1000);
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
          --bom:#248a3d; --medio:#c93400; --ruim:#d70015; --pres:#0a63c9; --borda:#e5e5ea; --on:#fff; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#000; --card:#1c1c1e; --txt:#f5f5f7; --sub:#98989d; --trilho:#3a3a3c;
            --bom:#30d158; --medio:#ff9f0a; --ruim:#ff453a; --pres:#409cff; --borda:#2c2c2e; --on:#000; }
  }
  * { box-sizing:border-box; }
  ::selection { background:color-mix(in srgb, var(--pres) 28%, transparent); }
  body { margin:0; background:var(--bg); color:var(--txt); font:15px/1.45 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;
         font-variant-numeric:tabular-nums; -webkit-font-smoothing:antialiased; }
  main { max-width:1100px; margin:0 auto; padding:40px 16px 56px; }
  h1 { font-size:34px; line-height:1.1; letter-spacing:-.025em; margin:0 0 6px; }
  .sub { color:var(--sub); margin:0 0 28px; font-size:14px; text-wrap:pretty; }
  .grade { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; align-items:start; }
  .card { --nivel:var(--bom); background:var(--card); border:1px solid var(--borda); border-radius:16px; padding:20px 20px 16px;
          transition:box-shadow .2s cubic-bezier(.16,1,.3,1); }
  .card.medio { --nivel:var(--medio); } .card.ruim { --nivel:var(--ruim); }
  .card:hover { box-shadow:0 8px 24px -12px rgb(0 0 0 / .18); }
  summary:focus-visible { outline:2px solid var(--pres); outline-offset:6px; border-radius:10px; }
  h2 { font-size:16px; line-height:1.25; margin:0; letter-spacing:-.01em; text-wrap:balance; }
  .hero { display:flex; align-items:center; gap:14px; margin-top:14px; }
  .big { font-size:56px; line-height:.9; font-weight:700; letter-spacing:-.04em; color:var(--nivel); min-width:1ch; }
  .hero-txt { display:flex; flex-direction:column; line-height:1.25; }
  .hero-txt b { font-size:16px; color:var(--nivel); }
  .hero-txt span { color:var(--sub); font-size:13px; }
  .blocos { display:flex; gap:4px; margin-top:14px; }
  .blocos i { flex:1; height:10px; border-radius:3px; background:var(--trilho); }
  .blocos i.livre { background:var(--nivel); }
  .stats { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-top:20px; }
  .k { color:var(--sub); font-size:12px; font-weight:500; }
  .v { font-size:20px; font-weight:650; letter-spacing:-.02em; line-height:1.3; }
  .v small { font-size:14px; font-weight:500; color:var(--sub); letter-spacing:0; }
  .nota { color:var(--sub); font-size:12px; margin-top:6px; }
  .trilho { height:4px; background:var(--trilho); border-radius:2px; margin-top:6px; overflow:hidden; }
  .barra { height:100%; border-radius:2px; }
  .barra.pres { background:var(--pres); }
  .barra.falt { background:var(--nivel); }
  footer { display:flex; justify-content:space-between; align-items:flex-end; gap:12px; margin-top:18px; padding-top:12px;
           border-top:1px solid var(--borda); color:var(--sub); font-size:12.5px; }
  .prox { color:var(--txt); margin-bottom:2px; } .prox b { font-weight:600; }
  .aviso { background:#fff4e5; color:#8a4b00; border:1px solid #ffd8a8; padding:10px 14px; border-radius:10px; margin-bottom:20px; font-size:14px; }
  @media (prefers-color-scheme: dark) { .aviso { background:#3a2a10; color:#ffcf8a; border-color:#5c4214; } }
  .topo { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; }
  #atualizar { font:inherit; font-size:14px; font-weight:600; padding:8px 16px; border-radius:980px; border:0;
               background:var(--pres); color:var(--on); cursor:pointer; }
  #atualizar:disabled { opacity:.6; cursor:default; }
  a#atualizar { text-decoration:none; display:inline-block; }
  a#atualizar[aria-busy] { opacity:.6; cursor:default; }
  .acoes { display:flex; gap:8px; align-items:center; margin:0; }
  .sair { font:inherit; font-size:14px; padding:8px 14px; border-radius:980px; border:1px solid var(--borda);
          background:transparent; color:var(--sub); cursor:pointer; }
  .rodape { color:var(--sub); font-size:12px; margin-top:28px; }
  summary { list-style:none; cursor:pointer; } summary::-webkit-details-marker { display:none; }
  .ver-cal { display:inline-flex; align-items:center; gap:2px; color:var(--pres); font-weight:500; white-space:nowrap; }
  .seta { display:block; transition:transform .2s cubic-bezier(.16,1,.3,1); }
  details[open] .ver-cal .seta { transform:rotate(180deg); }
  .cal { margin-top:12px; padding-top:12px; border-top:1px solid var(--borda); font-size:12px; }
  .mes { max-width:260px; margin:0 auto; }
  .nav-mes { display:flex; justify-content:center; gap:24px; margin-top:8px; }
  .nav-mes button { display:grid; place-items:center; width:36px; height:32px; border-radius:8px; border:1px solid var(--borda);
                    background:transparent; color:var(--txt); cursor:pointer; }
  .nav-mes button:hover:not(:disabled) { background:var(--trilho); }
  .nav-mes button:focus-visible, #atualizar:focus-visible, .sair:focus-visible { outline:2px solid var(--pres); outline-offset:2px; }
  .nav-mes button:disabled { opacity:.3; cursor:default; }
  .mes-nome { font-weight:600; text-transform:capitalize; margin-bottom:4px; }
  .dias { display:grid; grid-template-columns:repeat(7,1fr); gap:2px; text-align:center; }
  .dias b { color:var(--sub); font-weight:500; font-size:10px; }
  .dias span { border-radius:5px; padding:2px 0; color:var(--sub); }
  .dias .aula { background:var(--pres); color:var(--on); }
  .dias .foi { background:var(--trilho); color:var(--txt); }
  .dias .falta { background:var(--ruim); color:var(--on); font-weight:600; }
  .dias .feriado { background:repeating-linear-gradient(45deg,var(--trilho) 0 3px,transparent 3px 6px); color:var(--txt); text-decoration:line-through; }
  .dias .hoje { position:relative; z-index:1; font-weight:800; color:var(--txt); box-shadow:0 0 0 2px var(--card), 0 0 0 4px var(--medio); }
  .dias .hoje.aula, .dias .hoje.falta { color:var(--on); }
  .legenda { display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; color:var(--sub); }
  .legenda span::before { content:''; display:inline-block; width:10px; height:10px; border-radius:3px; margin-right:4px; vertical-align:-1px; }
  .legenda .aula::before { background:var(--pres); } .legenda .foi::before { background:var(--trilho); }
  .legenda .falta::before { background:var(--ruim); }
  .legenda .hoje::before { box-shadow:inset 0 0 0 2px var(--medio); }
  .legenda .feriado::before { background:repeating-linear-gradient(45deg,var(--sub) 0 2px,transparent 2px 4px); }
  .cal-feriados, .cal-vazio { color:var(--sub); margin-top:8px; }
</style>
</head>
<body data-atualizado="${esc(atualizadoEm)}">
<script>
  function trocarMes(b, passo) {
    const cal = b.closest('.cal'), meses = [...cal.querySelectorAll('.mes')], i = meses.findIndex((x) => !x.hidden);
    const j = Math.min(meses.length - 1, Math.max(0, i + passo));
    meses[i].hidden = true; meses[j].hidden = false;
    const [ant, prox] = cal.querySelectorAll('.nav-mes button');
    ant.disabled = j === 0; prox.disabled = j === meses.length - 1;
  }
  // Troca os cartões pelos da página nova sem recarregar (o .topo com o botão fica)
  async function recarregar(url = location.href) {
    const r = await fetch(url, { cache: 'no-store' });
    const novo = new DOMParser().parseFromString(await r.text(), 'text/html');
    if (!r.ok || !novo.querySelector('.grade')) return location.reload(); // ex.: sessão expirou e veio a tela de login
    const main = document.querySelector('main');
    main.replaceChildren(main.querySelector('.topo'), ...[...novo.querySelector('main').children].filter((e) => !e.matches('.topo')));
    document.body.dataset.atualizado = novo.body.dataset.atualizado;
  }
  // Site multiusuário: o link "Atualizar" busca os dados sem sair da página
  document.addEventListener('click', async (e) => {
    const a = e.target.closest('a#atualizar');
    if (!a || a.getAttribute('aria-busy')) return;
    e.preventDefault();
    a.setAttribute('aria-busy', 'true'); a.textContent = 'Atualizando…';
    try { await recarregar(a.href); } catch { location.href = a.href; return; }
    a.removeAttribute('aria-busy'); a.textContent = 'Atualizar';
  });
  // Abre e fecha o calendário deslizando (o <details> sozinho só pula)
  document.addEventListener('click', (e) => {
    const s = e.target.closest('.card > summary');
    if (!s || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    e.preventDefault();
    const d = s.parentElement, cal = d.querySelector('.cal');
    const abrindo = !d.open || d.dataset.fechando === '1'; // clique no meio do fechamento reabre
    const agora = getComputedStyle(cal); // parte de onde a animação anterior parou
    const atual = { height: agora.height, paddingTop: agora.paddingTop, marginTop: agora.marginTop, opacity: agora.opacity };
    const veioDoMeio = cal.getAnimations().length > 0;
    cal.getAnimations().forEach((a) => a.cancel());
    d.open = true;
    d.dataset.fechando = abrindo ? '' : '1';
    const fechado = { height: '0px', paddingTop: '0px', marginTop: '0px', opacity: 0 };
    const aberto = { height: cal.offsetHeight + 'px', paddingTop: '12px', marginTop: '12px', opacity: 1 };
    cal.style.overflow = 'hidden';
    const a = cal.animate([veioDoMeio ? atual : abrindo ? fechado : aberto, abrindo ? aberto : fechado],
      abrindo ? { duration: 280, easing: 'cubic-bezier(.16,1,.3,1)' } : { duration: 200, easing: 'cubic-bezier(.4,0,.2,1)' });
    a.onfinish = () => { cal.style.overflow = ''; if (!abrindo) { d.open = false; d.dataset.fechando = ''; } };
  });
</script>
<main>
  <div class="topo">
    <h1>Frequência</h1>
    ${botao}
  </div>
  <p class="sub">Atualizado ${esc(dataBR(atualizadoEm, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }))}${esc(quandoProxima)} · ordenado por quanto ainda dá pra faltar</p>
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
