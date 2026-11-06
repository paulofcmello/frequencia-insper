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
      const dica = faltas.has(iso) ? 'Falta' : feriados[iso] ? 'Feriado: ' + feriados[iso] : aulas[iso] ? 'Aula ' + aulas[iso].join(', ') + '' : '';
      const classe = `class="${tipo}${iso === hoje ? ' hoje' : ''}"${dica ? ` title="${esc(dica)}"` : ''}`;
      // Aula futura é botão: com o simulador ligado, o toque marca "vou faltar" ou "vou com certeza"
      dias += tipo === 'aula'
        ? `<button type="button" ${classe} data-dia="${iso}" data-n="${aulas[iso].length}" aria-pressed="false">${i}</button>`
        : `<span ${classe}>${i}</span>`;
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
    <div class="legenda"><span class="aula">aula</span><span class="foi">presença</span><span class="falta">falta</span><span class="feriado">feriado</span><span class="hoje">hoje</span><span class="plano so-sim">falta simulada</span><span class="vou so-sim">presença simulada</span></div>
    <div class="so-sim">
      <div class="modo-toque" role="group" aria-label="O que o toque marca"><button type="button" data-modo="falta" aria-pressed="true">Simular falta</button><button type="button" data-modo="vou" aria-pressed="false">Simular presença</button></div>
      <div class="cal-dica">${DICA_FALTA}</div>
    </div>
    ${listaFeriados ? '<div class="cal-feriados">Feriados sem aula: ' + listaFeriados + '</div>' : ''}`;
}

const DICA_FALTA = 'Toque numa aula futura pra simular uma falta.';
const DICA_VOU = 'Toque numa aula que você vai com certeza (ex.: prova): ela conta como presença e sai das que dá pra faltar.';

// Portal manda nomes em caixa alta; deixa legível sem estragar algarismos romanos
const MINUSCULAS = new Set(['a', 'o', 'e', 'de', 'da', 'do', 'das', 'dos', 'em', 'na', 'no', 'para', 'com']);
const nomeBonito = (s) => String(s).toLowerCase().split(' ')
  .map((p, i) => /^[ivx]+$/.test(p) ? p.toUpperCase() : i && MINUSCULAS.has(p) ? p : p.charAt(0).toUpperCase() + p.slice(1))
  .join(' ');

const seta = (d) => `<svg class="seta" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="${d}" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const SETA_BAIXO = seta('M4 6l4 4 4-4'), SETA_ESQ = seta('M10 4L6 8l4 4'), SETA_DIR = seta('M6 4l4 4-4 4');

const ALCA = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">'
  + [[6, 4], [10, 4], [6, 8], [10, 8], [6, 12], [10, 12]].map(([x, y]) => `<circle cx="${x}" cy="${y}" r="1.3" fill="currentColor"/>`).join('')
  + '</svg>';

// Opções do menu de ordem: valor, nome e o que significa
const OPCOES_ORDEM = [
  ['risco', '% que dá pra faltar', 'menor % das aulas restantes primeiro'],
  ['pode', 'Faltas sobrando', 'menos faltas livres primeiro'],
  ['prox', 'Próxima aula', 'a aula mais cedo primeiro'],
  ['nome', 'Nome', 'ordem alfabética'],
  ['custom', 'Personalizada', 'arraste os cartões pela alça'],
];
const CHECK = '<svg class="check" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function cartao(m, i) {
  const podeFaltar = Math.max(0, Math.min(m.restantes, m.aulasRestantes));
  const pct = m.aulasRestantes > 0 ? Math.round((podeFaltar / m.aulasRestantes) * 100) : 0;
  const f = folga(m);
  const nivel = m.restantes <= 0 || f < 0.25 ? 'ruim' : f < 0.5 ? 'medio' : 'bom';
  const plural = (n, um, varios) => n + ' ' + (n === 1 ? um : varios);
  // Lê como frase: "Pode faltar / 4 de 7 aulas restantes"
  const [heroTitulo, heroNum, heroSub] = m.restantes < 0
    ? ['Passou do limite', '+' + -m.restantes, -m.restantes === 1 ? 'falta a mais' : 'faltas a mais']
    : m.aulasRestantes <= 0
      ? ['Aulas encerradas', '', 'nenhuma aula restante']
      : [m.restantes === 0 ? 'Não pode mais faltar' : 'Pode faltar', podeFaltar,
         'de ' + plural(m.aulasRestantes, 'aula restante', 'aulas restantes') + (m.restantes > 0 ? ' · ' + pct + '%' : '')];
  // Um bloco por aula restante: cheios são as que ainda dá pra faltar
  const blocos = Array.from({ length: m.aulasRestantes }, (_, j) => `<i style="--n:${j}"${j < podeFaltar ? ' class="livre"' : ''}></i>`).join('');
  const faltamPresencas = Math.max(0, m.presencasNecessarias - m.presencas);
  const notaPresencas = faltamPresencas === 0 ? 'presença garantida' : 'faltam ' + faltamPresencas + ' de ' + m.aulasRestantes;
  const barra = (v, t) => (t > 0 ? Math.min(100, Math.max(0, (v / t) * 100)) : 0).toFixed(1);
  const ultimas = m.datas.slice(-3).map((d) => d.slice(0, 5)).join(', '); // DD/MM/AAAA → DD/MM
  const curta = (t, opc) => esc(dataBR(t, opc).replace('.', ''));

  return `
  <details class="card ${nivel}" style="--c:${i}" data-i="${i}" data-nome="${esc(m.nome)}" data-pode="${m.restantes < 0 ? m.restantes : podeFaltar}" data-prox="${m.proximaAula || ''}"
    data-restantes="${m.restantes}" data-aulas-restantes="${m.aulasRestantes}" data-faltas="${m.faltas}" data-permitidas="${m.permitidas}"
    data-chave="${m.faltas}|${m.presencas}|${m.restantes}|${m.aulasRestantes}|${m.proximaAula || ''}" data-aulas="${esc(JSON.stringify(m.diasAula || []))}">
    <summary>
    <div class="cab">
      <h2>${esc(nomeBonito(m.nome))}</h2>
      <button type="button" class="alca" aria-label="Mover ${esc(nomeBonito(m.nome))} (arraste ou use as setas)">${ALCA}</button>
    </div>
    <div class="hero">
      <div class="hero-topo">
        <b class="hero-titulo">${heroTitulo}</b>
        <span class="garantida" title="Já tem presenças suficientes: mesmo faltando todas as aulas restantes, passa por frequência"${faltamPresencas === 0 ? '' : ' hidden'}>${CHECK}Presença garantida</span>
      </div>
      <div class="hero-linha">${heroNum !== '' ? `<span class="big">${heroNum}</span>` : ''}<span class="hero-sub">${heroSub}</span></div>
    </div>
    ${blocos ? `<div class="blocos" role="img" aria-label="${podeFaltar} de ${m.aulasRestantes} aulas restantes ainda podem ser faltadas">${blocos}</div>` : ''}
    <div class="sim" hidden>Simulando <b></b> <button type="button" class="limpar-sim">limpar</button></div>
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
        <div class="nota">${ultimas ? esc(ultimas) : 'nenhuma falta'}</div>
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
          --bom:#248a3d; --medio:#c93400; --ruim:#d70015; --pres:#0a63c9; --borda:#e5e5ea; --on:#fff; --marca:#ffcc00; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#000; --card:#1c1c1e; --txt:#f5f5f7; --sub:#98989d; --trilho:#3a3a3c;
            --bom:#30d158; --medio:#ff9f0a; --ruim:#ff453a; --pres:#409cff; --borda:#2c2c2e; --on:#000; --marca:#ffd60a; }
  }
  * { box-sizing:border-box; }
  ::selection { background:color-mix(in srgb, var(--pres) 28%, transparent); }
  body { margin:0; background:var(--bg); color:var(--txt); font:15px/1.45 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;
         font-variant-numeric:tabular-nums; -webkit-font-smoothing:antialiased; }
  main { max-width:1100px; margin:0 auto; padding:24px 16px 40px; }
  h1 { font-size:28px; line-height:1.1; letter-spacing:-.025em; margin:0; }
  .sub { color:var(--sub); margin:0; font-size:14px; text-wrap:pretty; }
  .titulo { display:flex; align-items:baseline; gap:2px 14px; flex-wrap:wrap; }
  /* Botão de menu no estilo do macOS: pílula cinza, ícone, valor atual e chevron duplo; o menu aberto é o nativo */
  .ordem { position:relative; display:inline-flex; align-items:center; align-self:center; gap:6px; color:var(--sub); font-size:14px; }
  #ordem { display:inline-flex; align-items:center; gap:3px; font:inherit; font-size:13px; font-weight:600; color:var(--txt);
           background:var(--trilho); border:0; border-radius:980px; padding:4px 8px 4px 12px; cursor:pointer; transition:background-color .15s; }
  #ordem:hover, #ordem[aria-expanded=true] { background:color-mix(in srgb, var(--trilho) 86%, var(--txt)); }
  #ordem:focus-visible { outline:2px solid var(--pres); outline-offset:2px; }
  #ordem[aria-expanded=true] .seta { transform:rotate(180deg); }
  .ordem-menu { position:absolute; top:calc(100% + 6px); left:0; z-index:10; min-width:260px; margin:0; padding:6px; list-style:none;
                background:var(--card); border-radius:14px; box-shadow:0 0 0 1px var(--borda), 0 16px 36px -12px rgb(0 0 0 / .28);
                transform-origin:top left; transition:opacity .18s cubic-bezier(.16,1,.3,1), transform .18s cubic-bezier(.16,1,.3,1); }
  @starting-style { .ordem-menu { opacity:0; transform:translateY(-4px) scale(.97); } }
  .ordem-menu li { display:grid; grid-template-columns:1fr auto; column-gap:14px; align-items:center; padding:7px 10px;
                   border-radius:9px; cursor:pointer; outline:none; line-height:1.3; }
  .ordem-menu li:hover, .ordem-menu li:focus { background:var(--trilho); }
  .ordem-menu b { font-size:14px; font-weight:500; color:var(--txt); }
  .ordem-menu small { grid-column:1; font-size:12px; color:var(--sub); }
  .ordem-menu .check { grid-column:2; grid-row:1 / span 2; color:var(--pres); visibility:hidden; }
  .ordem-menu [aria-selected=true] b { color:var(--pres); font-weight:600; }
  .ordem-menu [aria-selected=true] .check { visibility:visible; }
  .cab { display:flex; justify-content:space-between; align-items:flex-start; gap:8px; }
  .hero-topo { display:flex; justify-content:space-between; align-items:center; gap:8px; }
  .garantida { display:inline-flex; align-items:center; gap:4px; flex:none; padding:2px 9px 2px 7px; border-radius:980px; white-space:nowrap;
               font-size:12px; font-weight:600; color:var(--bom); background:color-mix(in srgb, var(--bom) 14%, transparent); }
  .garantida .check { visibility:visible; }
  .garantida[hidden] { display:none; }
  .alca { display:none; place-items:center; flex:none; width:28px; height:28px; margin:-5px -8px -5px 0; padding:0; border:0; border-radius:6px;
          background:transparent; color:var(--sub); cursor:grab; touch-action:none; }
  main.personalizada .alca { display:grid; }
  .alca:hover { background:var(--trilho); color:var(--txt); }
  .alca:focus-visible { outline:2px solid var(--pres); outline-offset:1px; }
  .card.arrastando { position:relative; z-index:3; pointer-events:none; box-shadow:0 24px 48px -16px rgb(0 0 0 / .4); }
  body.arrastando, body.arrastando * { cursor:grabbing !important; user-select:none; }
  .grade { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; align-items:start; }
  .card { --nivel:var(--bom); background:var(--card); border:1px solid var(--borda); border-radius:16px; padding:16px 18px 12px;
          transition:box-shadow .2s cubic-bezier(.16,1,.3,1); }
  .card.medio { --nivel:var(--medio); } .card.ruim { --nivel:var(--ruim); }
  .card:hover { box-shadow:0 8px 24px -12px rgb(0 0 0 / .18); }
  summary:focus-visible { outline:2px solid var(--pres); outline-offset:6px; border-radius:10px; }
  h2 { font-size:16px; line-height:1.25; margin:0; letter-spacing:-.01em; text-wrap:balance; }
  .hero { margin-top:8px; }
  .hero-titulo { display:block; font-size:15px; color:var(--nivel); }
  .hero-linha { display:flex; align-items:baseline; gap:10px; }
  .big { font-size:44px; line-height:.9; font-weight:700; letter-spacing:-.04em; color:var(--nivel); min-width:1ch; }
  .hero-sub { color:var(--sub); font-size:14px; }
  .blocos { display:flex; gap:4px; margin-top:10px; }
  .blocos i { flex:1; height:8px; border-radius:3px; background:var(--trilho); }
  .blocos i.livre { background:var(--nivel); }
  .stats { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-top:12px; }
  .k { color:var(--sub); font-size:12px; font-weight:500; }
  .v { font-size:20px; font-weight:650; letter-spacing:-.02em; line-height:1.3; }
  .v small { font-size:14px; font-weight:500; color:var(--sub); letter-spacing:0; }
  .nota { color:var(--sub); font-size:12px; margin-top:4px; }
  .trilho { height:4px; background:var(--trilho); border-radius:2px; margin-top:6px; overflow:hidden; }
  .barra { height:100%; border-radius:2px; }
  /* Ao abrir: barras crescem e os blocos livres se acendem um a um, cartão por cartão */
  @keyframes crescer { from { transform:scaleX(0); } }
  @keyframes acender { from { background:var(--trilho); transform:scaleY(.5); } }
  @keyframes pulsar { from { box-shadow:0 0 0 0 color-mix(in srgb, var(--nivel) 50%, transparent); } to { box-shadow:0 0 0 12px transparent; } }
  .barra { transform-origin:left; animation:crescer .8s cubic-bezier(.16,1,.3,1) both; animation-delay:calc(var(--c, 0) * 70ms + 80ms); }
  .blocos i.livre { animation:acender .4s cubic-bezier(.16,1,.3,1) both; animation-delay:calc(var(--c, 0) * 70ms + var(--n, 0) * 50ms + 150ms); }
  .card.sem-anim .barra, .card.sem-anim .blocos i { animation:none; } /* não mudou na atualização: fica quieto */
  .card.mudou { animation:pulsar 1.1s cubic-bezier(.16,1,.3,1) .25s 2; }
  @media (prefers-reduced-motion: reduce) { .barra, .blocos i, .card.mudou { animation:none !important; } }
  .barra.pres { background:var(--pres); }
  /* Falta nunca é verde: laranja normal, vermelho quando a matéria está apertada */
  .barra.falt { background:var(--medio); } .card.ruim .barra.falt { background:var(--ruim); }
  footer { display:flex; justify-content:space-between; align-items:flex-end; gap:12px; margin-top:12px; padding-top:10px;
           border-top:1px solid var(--borda); color:var(--sub); font-size:12.5px; }
  .prox { color:var(--txt); margin-bottom:2px; } .prox b { font-weight:600; }
  .aviso { background:#fff4e5; color:#8a4b00; border:1px solid #ffd8a8; padding:10px 14px; border-radius:10px; margin-bottom:20px; font-size:14px; }
  @media (prefers-color-scheme: dark) { .aviso { background:#3a2a10; color:#ffcf8a; border-color:#5c4214; } }
  .topo { display:flex; justify-content:space-between; align-items:center; gap:12px 16px; flex-wrap:wrap; margin-bottom:16px; }
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
  .cal-feriados, .cal-vazio, .cal-dica { color:var(--sub); margin-top:8px; }
  .dias button { font:inherit; color:inherit; border:0; padding:2px 0; border-radius:5px; cursor:pointer; transition:filter .15s, box-shadow .15s; }
  .dias button:hover { filter:brightness(1.12); }
  .dias button:focus-visible { outline:2px solid var(--txt); outline-offset:1px; }
  .dias .plano, .dias .plano.hoje { background:color-mix(in srgb, var(--ruim) 14%, transparent); color:var(--ruim);
                                    box-shadow:inset 0 0 0 1.5px var(--ruim); font-weight:700; }
  .legenda .plano::before { box-shadow:inset 0 0 0 1.5px var(--ruim); }
  .blocos i.plano { background:transparent; box-shadow:inset 0 0 0 1.5px var(--ruim); }
  .sim { display:flex; align-items:center; gap:6px; margin-top:8px; font-size:12px; color:var(--ruim); }
  .sim[hidden] { display:none; }
  .limpar-sim { font:inherit; padding:0; border:0; background:none; color:var(--pres); cursor:pointer; text-decoration:underline; text-underline-offset:2px; }
  #so-hoje { font:inherit; font-size:13px; font-weight:600; color:var(--txt); background:var(--trilho); border:0; border-radius:980px;
             padding:4px 12px; cursor:pointer; align-self:center; transition:background-color .15s, color .15s; }
  #so-hoje:hover { background:color-mix(in srgb, var(--trilho) 86%, var(--txt)); }
  #so-hoje[aria-pressed=true] { background:var(--pres); color:var(--on); }
  #so-hoje:focus-visible { outline:2px solid var(--pres); outline-offset:2px; }
  .vazio-hoje { color:var(--sub); margin:8px 0 0; }
  /* Switch do simulador, no estilo do iOS */
  .switch { display:inline-flex; align-items:center; gap:8px; align-self:center; font-size:13px; font-weight:600; color:var(--txt); cursor:pointer; user-select:none; }
  #simulador { position:relative; flex:none; width:38px; height:22px; padding:0; border:0; border-radius:980px; background:var(--trilho); cursor:pointer;
               transition:background-color .2s cubic-bezier(.16,1,.3,1); }
  #simulador::after { content:''; position:absolute; top:2px; left:2px; width:18px; height:18px; border-radius:50%; background:#fff;
                      box-shadow:0 1px 3px rgb(0 0 0 / .25); transition:transform .2s cubic-bezier(.16,1,.3,1); }
  #simulador[aria-checked=true] { background:var(--bom); }
  #simulador[aria-checked=true]::after { transform:translateX(16px); }
  #simulador:focus-visible { outline:2px solid var(--pres); outline-offset:2px; }
  @media (prefers-reduced-motion: reduce) { #simulador, #simulador::after { transition:none; } }
  /* Simulador desligado: calendário só mostra, toque não marca nada */
  main:not(.simulando) .so-sim { display:none; }
  main:not(.simulando) .dias button { pointer-events:none; }
  .dias .vou, .dias .vou.hoje { background:var(--marca); color:#1d1d1f; font-weight:700; }
  .legenda .vou::before { background:var(--marca); }
  .blocos i.vou { background:color-mix(in srgb, var(--marca) 70%, transparent); }
  .modo-toque { display:flex; gap:4px; margin-top:10px; padding:2px; border-radius:9px; background:var(--trilho); width:max-content; }
  .modo-toque button { font:inherit; font-size:12px; font-weight:500; padding:4px 10px; border:0; border-radius:7px; background:transparent; color:var(--sub); cursor:pointer; }
  .modo-toque [aria-pressed=true] { background:var(--card); color:var(--txt); font-weight:600; box-shadow:0 1px 3px rgb(0 0 0 / .15); }
  .modo-toque button:focus-visible { outline:2px solid var(--pres); outline-offset:1px; }
  /* Visual "premium" (Liquid Glass): só vale com html.premium; o original fica intacto */
  html.premium { --bg:#f2f2f7; --card:rgb(255 255 255 / .62); --borda:rgb(0 0 0 / .06); --trilho:rgb(120 120 128 / .16);
                 --vidro:rgb(255 255 255 / .55); --brilho:rgb(255 255 255 / .9); --sombra:rgb(30 40 80 / .12); }
  @media (prefers-color-scheme: dark) {
    html.premium { --bg:#000; --card:rgb(44 44 46 / .55); --borda:rgb(255 255 255 / .08); --trilho:rgb(120 120 128 / .28);
                   --vidro:rgb(40 40 44 / .5); --brilho:rgb(255 255 255 / .14); --sombra:rgb(0 0 0 / .5); }
  }
  /* Fundo com cor suave e fixa: é o que o vidro refrata */
  .premium body { font-size:16px; letter-spacing:-.01em; min-height:100vh;
    background:radial-gradient(60vw 50vh at 8% 0%, color-mix(in srgb, var(--pres) 22%, transparent), transparent 70%),
               radial-gradient(50vw 45vh at 95% 15%, color-mix(in srgb, #bf5af2 16%, transparent), transparent 70%),
               radial-gradient(70vw 60vh at 50% 110%, color-mix(in srgb, #30d5c8 14%, transparent), transparent 70%), var(--bg);
    background-attachment:fixed; }
  .premium main { max-width:1180px; padding:14px 22px 104px; }
  /* Material de vidro: translúcido, desfoque forte, brilho na borda de cima, sombra macia deslocada */
  .premium .topo, .premium .card, .premium .versao, .premium .ordem-menu {
    background:var(--vidro); backdrop-filter:blur(28px) saturate(190%); -webkit-backdrop-filter:blur(28px) saturate(190%);
    box-shadow:inset 0 1px 0 var(--brilho), inset 0 0 0 1px var(--borda), 0 1px 2px rgb(0 0 0 / .04), 0 14px 36px -14px var(--sombra); }
  .premium .card { background:var(--card); }
  .premium .topo { position:sticky; top:12px; z-index:5; margin:0 0 26px; padding:10px 10px 10px 22px; border-radius:28px; }
  .premium .titulo { align-items:center; gap:6px 14px; }
  .premium h1 { font-size:22px; font-weight:700; letter-spacing:-.025em; }
  .premium .sub { font-size:13px; }
  .premium .ordem { font-size:13px; }
  /* Mola do Liquid Glass: passa um pouco do ponto e assenta */
  html { --mola:linear(0, .08 3%, .3 8%, .62 14%, .88 21%, 1.04 28%, 1.09 34%, 1.08 40%, 1.03 50%, .995 62%, .992 72%, 1); }
  /* Controles da barra: vidro por dentro do vidro (sem desfoque próprio), crescem e acendem onde o dedo toca */
  .premium #ordem, .premium #so-hoje, .premium #atualizar {
    --luz:rgb(255 255 255 / 0); position:relative;
    background:radial-gradient(circle at var(--gx, 50%) var(--gy, 50%), var(--luz), transparent 70%),
               linear-gradient(180deg, rgb(255 255 255 / .82), rgb(255 255 255 / .42));
    box-shadow:inset 0 1px 0 rgb(255 255 255 / .95), inset 0 -1px 0 rgb(255 255 255 / .35), inset 0 0 0 1px var(--borda),
               0 1px 2px rgb(0 0 0 / .05), 0 6px 14px -6px var(--sombra);
    transition:transform .5s var(--mola), box-shadow .3s, --luz .4s; }
  @media (prefers-color-scheme: dark) { .premium #ordem, .premium #so-hoje {
    background:radial-gradient(circle at var(--gx, 50%) var(--gy, 50%), var(--luz), transparent 70%),
               linear-gradient(180deg, rgb(255 255 255 / .16), rgb(255 255 255 / .05));
    box-shadow:inset 0 1px 0 rgb(255 255 255 / .18), inset 0 0 0 1px var(--borda), 0 6px 14px -6px var(--sombra); } }
  .premium #so-hoje[aria-pressed=true], .premium #atualizar {
    background:radial-gradient(circle at var(--gx, 50%) var(--gy, 50%), var(--luz), transparent 70%),
               linear-gradient(180deg, rgb(255 255 255 / .28), rgb(255 255 255 / 0) 60%), var(--pres);
    box-shadow:inset 0 1px 0 rgb(255 255 255 / .45), inset 0 0 0 1px rgb(0 0 0 / .06), 0 8px 18px -8px color-mix(in srgb, var(--pres) 80%, transparent); }
  .premium #ordem:active, .premium #so-hoje:active, .premium #atualizar:active, .premium #ordem[aria-expanded=true] { transform:scale(1.08); --luz:rgb(255 255 255 / .7); }
  @property --luz { syntax:'<color>'; inherits:false; initial-value:transparent; }
  /* Switch do iOS 26: ao apertar, a bolinha vira uma lente de vidro larga e desliza com mola */
  /* Borda de vidro com aberração cromática (o arco-íris fino nas bordas da lente) */
  html { --arco:inset 0 1.5px 0 rgb(255 255 255 / .95), inset 2px 0 1px -1px rgb(255 90 120 / .7), inset -2px 0 1px -1px rgb(80 170 255 / .7),
                inset 0 -1.5px 1px -.5px rgb(120 255 200 / .55), inset 0 0 0 1px rgb(255 255 255 / .35), 0 8px 22px -4px rgb(0 0 0 / .3); }
  .premium #simulador::after { transition:transform .5s var(--mola), width .45s var(--mola), height .45s var(--mola), left .45s var(--mola),
                                         top .45s var(--mola), background-color .25s, box-shadow .25s; }
  /* Enquanto o dedo segura: a bolinha vira uma lente de vidro maior que o trilho, e só volta ao soltar */
  #simulador { touch-action:none; }
  #simulador.arrastando::after { transform:translateX(var(--kx)) !important; width:calc(18px + var(--kw, 0px));
                                 transition-property:height, left, top, background-color, box-shadow; }
  .premium #simulador.arrastando.apertado::after { width:calc(42px + var(--kw, 0px)); }
  .premium #simulador.apertado::after { top:-5px; left:-10px; width:42px; height:32px; background:rgb(255 255 255 / .1); box-shadow:var(--arco); }
  .premium #atualizar { padding:9px 20px; }
  .premium .sair { border:0; background:transparent; }
  .premium .sair:hover { color:var(--txt); }
  .premium .ordem-menu { border-radius:18px; background:color-mix(in srgb, var(--bg) 90%, transparent); } /* vidro dentro de vidro some no Safari */
  .premium .grade { gap:20px; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); }
  .premium .card { border:0; border-radius:26px; padding:18px 22px 12px;
                   transition:transform .5s cubic-bezier(.16,1,.3,1), box-shadow .5s cubic-bezier(.16,1,.3,1); }
  .premium .card.arrastando { transition:none; } /* o arrastado segue o dedo sem atraso */
  .premium body:not(.arrastando) .card:hover { transform:translateY(-3px);
    box-shadow:inset 0 1px 0 var(--brilho), inset 0 0 0 1px var(--borda), 0 2px 4px rgb(0 0 0 / .04), 0 30px 60px -22px var(--sombra); }
  .premium h2 { font-size:19px; font-weight:650; letter-spacing:-.02em; }
  .premium .hero { margin-top:8px; }
  .premium .big { font-size:52px; font-weight:700; letter-spacing:-.045em; }
  .premium .blocos { gap:3px; margin-top:12px; } .premium .blocos i { height:6px; border-radius:980px; }
  .premium .stats { margin-top:14px; gap:24px; }
  .premium .k { font-size:13px; } .premium .v { font-size:22px; font-weight:600; letter-spacing:-.03em; }
  .premium .trilho { height:5px; border-radius:980px; } .premium .barra { border-radius:980px; }
  .premium footer { margin-top:12px; padding-top:10px; }
  .premium .rodape { text-align:center; }
  @media (max-width:1000px) { .premium #ordem-rotulo { position:absolute; width:1px; height:1px; overflow:hidden; clip-path:inset(50%); } }
  @media (max-width:640px) { .premium .topo { border-radius:22px; padding:12px 14px; position:relative; top:0; } /* no celular ocupa muito pra ficar grudado */ .premium main { padding-inline:14px; } }
  @media (prefers-reduced-motion: reduce) { .premium body:not(.arrastando) .card:hover { transform:none; } }
  @media (prefers-reduced-transparency: reduce) { html.premium { --vidro:var(--bg); --card:var(--bg); } }
  /* Liquid Glass de verdade (só Chromium, html.lente): a barra e o alternador refratam o que passa por baixo, como lente */
  .premium .ordem-menu { backdrop-filter:none; -webkit-backdrop-filter:none; } /* vidro dentro de vidro quebra */
  /* --lente é um filtro SVG feito sob medida pra cada elemento (tamanho, cantos, tela) pelo script "lentes" */
  .premium.lente .topo, .premium.lente .versao, .premium.lente .card { backdrop-filter:var(--lente, blur(28px)) saturate(180%); -webkit-backdrop-filter:var(--lente, blur(28px)) saturate(180%); }
  /* Vidro quase incolor: a cor vem do fundo; o que desenha a peça é a borda polida */
  .premium.lente { --card:rgb(255 255 255 / .42); }
  @media (prefers-color-scheme: dark) { .premium.lente { --card:rgb(44 44 46 / .42); } }
  .premium.lente .topo, .premium.lente .versao { background:linear-gradient(180deg, color-mix(in srgb, var(--bg) 52%, transparent), color-mix(in srgb, var(--bg) 40%, transparent));
    box-shadow:inset 0 1px 0 var(--brilho), inset 0 -1px 0 rgb(255 255 255 / .25), inset 1px 0 0 rgb(255 255 255 / .18),
               inset -1px 0 0 rgb(255 255 255 / .18), inset 0 0 0 1px var(--borda), 0 1px 2px rgb(0 0 0 / .05), 0 16px 40px -14px var(--sombra); }
  @media (prefers-reduced-transparency: reduce) { .premium.lente .topo, .premium.lente .versao, .premium.lente .card { backdrop-filter:none; } }
  /* Alternador Original / Premium */
  .versao { touch-action:none; position:fixed; bottom:max(18px, env(safe-area-inset-bottom)); left:50%; transform:translateX(-50%); z-index:20;
            display:flex; padding:3px; isolation:isolate; border-radius:980px; background:color-mix(in srgb, var(--card) 72%, transparent);
            backdrop-filter:saturate(180%) blur(20px); -webkit-backdrop-filter:saturate(180%) blur(20px);
            box-shadow:0 0 0 1px var(--borda), 0 10px 30px -10px rgb(0 0 0 / .3); }
  .premium .versao { background:var(--vidro); }
  .versao button { font:inherit; font-size:13px; font-weight:600; padding:7px 16px; border:0; border-radius:980px;
                   background:transparent; color:var(--sub); cursor:pointer; transition:background-color .2s, color .2s, transform .2s; }
  .versao [aria-pressed=true] { color:var(--bg); }
  .versao .pilula { position:absolute; top:3px; bottom:3px; left:3px; z-index:-1; border-radius:980px; background:var(--txt);
                    transition:transform .5s var(--mola), background-color .25s, box-shadow .25s; }
  .versao.apertando .pilula { transform:scale(1.22, 1.3); background:rgb(255 255 255 / .1); box-shadow:var(--arco); }
  .versao.apertando [aria-pressed=true] { color:var(--txt); }
  @media (prefers-reduced-motion: reduce) { .versao .pilula, .premium #simulador::after, .premium #ordem, .premium #so-hoje, .premium #atualizar { transition:none; } }
  .versao button:focus-visible { outline:2px solid var(--pres); outline-offset:2px; }
</style>
<script>try { if (localStorage.versao === 'premium') document.documentElement.classList.add('premium'); } catch {}</script>
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
    // Só anima o que mudou: cartão igual ao de antes entra parado; o que mudou pisca e conta o número
    const antes = new Map(cartoes().map((c) => [c.dataset.nome, { chave: c.dataset.chave, big: c.querySelector('.big')?.textContent }]));
    for (const c of novo.querySelectorAll('.grade > .card')) {
      const a = antes.get(c.dataset.nome);
      if (a && a.chave === c.dataset.chave) c.classList.add('sem-anim');
      else if (a) { c.classList.add('mudou'); c.dataset.bigAntes = a.big ?? ''; }
    }
    const main = document.querySelector('main');
    main.replaceChildren(main.querySelector('.topo'), ...[...novo.querySelector('main').children].filter((e) => !e.matches('.topo')));
    main.querySelector('.sub').replaceWith(novo.querySelector('.sub')); // horário de atualização fica no .topo
    document.body.dataset.atualizado = novo.body.dataset.atualizado;
    aplicarOrdem(false);
    aplicarSim();
    filtrarHoje();
    document.querySelectorAll('.card.mudou').forEach(contar);
  }
  // Número grande vai do valor antigo ao novo
  function contar(c) {
    const el = c.querySelector('.big'), de = parseInt(c.dataset.bigAntes, 10), para = parseInt(el?.textContent, 10);
    if (!el || isNaN(de) || isNaN(para) || de === para || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const sinal = el.textContent.startsWith('+') ? '+' : '', t0 = performance.now();
    const passo = (t) => {
      const p = Math.min(1, (t - t0) / 700);
      el.textContent = sinal + Math.round(de + (para - de) * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(passo);
    };
    el.textContent = sinal + de;
    requestAnimationFrame(passo);
  }
  // Ordem dos cartões: escolhida no seletor e lembrada só neste navegador
  const CHAVE_ORDEM = 'frequencia-ordem';
  const lerOrdem = () => { try { return JSON.parse(localStorage.getItem(CHAVE_ORDEM)) || {}; } catch { return {}; } };
  const salvarOrdem = (o) => { try { localStorage.setItem(CHAVE_ORDEM, JSON.stringify(o)); } catch {} };
  const cartoes = () => [...document.querySelectorAll('.grade > .card')];
  const CRITERIOS = {
    risco: (a, b) => a.dataset.i - b.dataset.i, // o servidor já manda nessa ordem
    pode: (a, b) => a.dataset.pode - b.dataset.pode || a.dataset.i - b.dataset.i,
    prox: (a, b) => (+a.dataset.prox || Infinity) - (+b.dataset.prox || Infinity) || a.dataset.i - b.dataset.i,
    nome: (a, b) => a.dataset.nome.localeCompare(b.dataset.nome, 'pt-BR'),
  };
  // Anima os cartões da posição antiga pra nova (FLIP)
  function mover(mudar) {
    const antes = new Map(cartoes().map((c) => [c, c.getBoundingClientRect()]));
    mudar();
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    for (const [c, a] of antes) {
      if (c === arrastando || !a.width) continue; // o arrastado segue o dedo; o que estava escondido só aparece
      const d = c.getBoundingClientRect(), dx = a.left - d.left, dy = a.top - d.top;
      if (dx || dy) c.animate([{ transform: 'translate(' + dx + 'px,' + dy + 'px)' }, { transform: 'none' }], { id: 'flip', duration: 250, easing: 'cubic-bezier(.16,1,.3,1)' });
    }
  }
  function aplicarOrdem(animar) {
    const grade = document.querySelector('.grade');
    if (!grade) return;
    const o = lerOrdem(), modo = (CRITERIOS[o.modo] || o.modo === 'custom') ? o.modo : 'risco';
    marcarOrdem(modo);
    document.querySelector('main').classList.toggle('personalizada', modo === 'custom');
    const pos = new Map((o.lista || []).map((n, i) => [n, i])); // matéria nova vai pro fim
    const cmp = CRITERIOS[modo] || ((a, b) => (pos.get(a.dataset.nome) ?? 1e9) - (pos.get(b.dataset.nome) ?? 1e9) || a.dataset.i - b.dataset.i);
    const reordenar = () => cartoes().sort(cmp).forEach((c) => grade.append(c));
    animar ? mover(reordenar) : reordenar();
  }
  const salvarPersonalizada = () => salvarOrdem({ modo: 'custom', lista: cartoes().map((c) => c.dataset.nome) });
  document.addEventListener('DOMContentLoaded', () => { aplicarOrdem(false); ligarSimulador(simLigado()); });

  // Simulador (liga/desliga no topo): em cada aula futura marca "vou faltar" ou "vou com certeza" (ex.: prova).
  // Aula certa sai da conta das que dá pra faltar. Tudo guardado só neste navegador.
  const CHAVE_SIM = 'frequencia-simulacao', CHAVE_VOU = 'frequencia-vou', CHAVE_SIM_ON = 'frequencia-simulador';
  const hojeSP = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' });
  const ler = (k) => { try { return JSON.parse(localStorage.getItem(k)) || {}; } catch { return {}; } };
  const gravar = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} };
  const simLigado = () => { try { return localStorage.getItem(CHAVE_SIM_ON) === '1'; } catch { return false; } };
  const salvarSim = () => {
    const faltas = {}, vou = {};
    for (const c of cartoes()) {
      const f = [...c.querySelectorAll('.cal button.plano')].map((b) => b.dataset.dia);
      const v = [...c.querySelectorAll('.cal button.vou')].map((b) => b.dataset.dia);
      if (f.length) faltas[c.dataset.nome] = f;
      if (v.length) vou[c.dataset.nome] = v;
    }
    gravar(CHAVE_SIM, faltas);
    gravar(CHAVE_VOU, vou);
  };
  function ligarSimulador(on) {
    try { localStorage.setItem(CHAVE_SIM_ON, on ? '1' : '0'); } catch {}
    document.querySelector('main').classList.toggle('simulando', on);
    document.getElementById('simulador')?.setAttribute('aria-checked', on);
    aplicarSim();
  }
  // Desligado: cartões com os números reais; as marcações ficam guardadas pra quando ligar de novo
  function aplicarSim() {
    const on = simLigado(), faltas = on ? ler(CHAVE_SIM) : {}, vou = on ? ler(CHAVE_VOU) : {}, hoje = hojeSP();
    for (const c of cartoes()) {
      const f = new Set((faltas[c.dataset.nome] || []).filter((d) => d >= hoje)); // dia que passou não conta mais
      const v = new Set((vou[c.dataset.nome] || []).filter((d) => d >= hoje));
      c.querySelectorAll('.cal button[data-dia]').forEach((b) => marcar(b, f.has(b.dataset.dia) ? 'plano' : v.has(b.dataset.dia) ? 'vou' : ''));
      simular(c);
    }
  }
  function marcar(b, tipo) { b.classList.toggle('plano', tipo === 'plano'); b.classList.toggle('vou', tipo === 'vou'); b.setAttribute('aria-pressed', !!tipo); }
  // Mesma conta do servidor (cartao/folga), com as faltas simuladas somadas e as aulas certas fora das restantes
  function simular(c) {
    const hoje = hojeSP();
    const soma = (cls) => [...c.querySelectorAll('.cal button.' + cls)].filter((b) => b.dataset.dia >= hoje).reduce((t, b) => t + +b.dataset.n, 0);
    const k = soma('plano'), v = soma('vou'), R0 = +c.dataset.restantes, A0 = +c.dataset.aulasRestantes;
    const R = R0 - k, A = Math.max(0, A0 - v), F = +c.dataset.faltas + k, P = +c.dataset.permitidas;
    const pode = Math.max(0, Math.min(R, A)), pct = A > 0 ? Math.round((pode / A) * 100) : 0;
    const f = R < 0 ? -1 : A <= 0 ? 1 : Math.min(R, A) / A;
    const nivel = R <= 0 || f < 0.25 ? 'ruim' : f < 0.5 ? 'medio' : 'bom';
    c.classList.remove('bom', 'medio', 'ruim');
    c.classList.add(nivel);
    c.dataset.podeAgora = pode;
    c.dataset.nivelAgora = nivel;
    const big = c.querySelector('.big');
    if (big && A0 > 0) {
      const certas = v ? ' · fora ' + (v === 1 ? '1 presença' : v + ' presenças') : '';
      const [tit, num, sub] = R < 0
        ? ['Passou do limite', '+' + -R, -R === 1 ? 'falta a mais' : 'faltas a mais']
        : A === 0
          ? ['Vai em todas', 0, 'você marcou todas as aulas restantes']
          : [R === 0 ? 'Não pode mais faltar' : 'Pode faltar', pode, 'de ' + A + (A === 1 ? ' aula restante' : ' aulas restantes') + (R > 0 ? ' · ' + pct + '%' : '') + certas];
      c.querySelector('.hero-titulo').textContent = tit;
      big.textContent = num;
      c.querySelector('.hero-sub').textContent = sub;
    }
    // Presença garantida: as presenças que faltam cabem nas aulas certas
    const faltamPres = Math.max(0, A - R0);
    c.querySelector('.garantida').hidden = faltamPres > 0;
    c.querySelector('.stats > div:first-child .nota').textContent = faltamPres === 0 ? 'presença garantida' : 'faltam ' + faltamPres + ' de ' + A;
    const planejados = Math.min(k, A - pode);
    c.querySelectorAll('.blocos i').forEach((b, j) => {
      b.classList.toggle('livre', j < pode);
      b.classList.toggle('plano', j >= pode && j < pode + planejados);
      b.classList.toggle('vou', j >= A0 - v);
    });
    const vf = c.querySelector('.stats > div:nth-child(2) .v');
    vf.firstChild.textContent = F;
    c.querySelector('.barra.falt').style.width = (P > 0 ? Math.min(100, (F / P) * 100) : 0).toFixed(1) + '%';
    const partes = [k && (k === 1 ? '1 falta' : k + ' faltas'), v && (v === 1 ? '1 presença' : v + ' presenças')].filter(Boolean);
    const aviso = c.querySelector('.sim');
    aviso.hidden = !partes.length;
    aviso.querySelector('b').textContent = partes.join(' e ');
  }
  document.addEventListener('click', (e) => {
    if (e.target.closest('#simulador')) return ligarSimulador(!simLigado());
    const modo = e.target.closest('.modo-toque button');
    if (modo) {
      const cal = modo.closest('.cal');
      cal.dataset.modo = modo.dataset.modo;
      cal.querySelectorAll('.modo-toque button').forEach((x) => x.setAttribute('aria-pressed', x === modo));
      cal.querySelector('.cal-dica').textContent = modo.dataset.modo === 'vou' ? ${JSON.stringify(DICA_VOU)} : ${JSON.stringify(DICA_FALTA)};
      return;
    }
    const b = e.target.closest('main.simulando .cal button[data-dia]');
    const limpar = e.target.closest('.limpar-sim');
    if (!b && !limpar) return;
    e.preventDefault(); // "limpar" fica dentro do <summary>: não abre/fecha o calendário
    const c = (b || limpar).closest('.card');
    if (b) {
      const tipo = b.closest('.cal').dataset.modo === 'vou' ? 'vou' : 'plano';
      marcar(b, b.classList.contains(tipo) ? '' : tipo); // tocar de novo desmarca; trocar de modo troca a marca
    } else c.querySelectorAll('.cal button[data-dia]').forEach((x) => marcar(x, ''));
    simular(c);
    salvarSim();
  });

  // Botão "Hoje": mostra só as matérias com aula hoje
  function filtrarHoje() {
    const b = document.getElementById('so-hoje'), vazio = document.querySelector('.vazio-hoje');
    if (!b || !vazio) return;
    const ligado = b.getAttribute('aria-pressed') === 'true', hoje = hojeSP();
    mover(() => {
      for (const c of cartoes()) c.hidden = ligado && !JSON.parse(c.dataset.aulas || '[]').some((d) => d.startsWith(hoje));
    });
    vazio.hidden = !ligado || cartoes().some((c) => !c.hidden);
  }
  document.addEventListener('click', (e) => {
    const b = e.target.closest('#so-hoje');
    if (!b) return;
    b.setAttribute('aria-pressed', b.getAttribute('aria-pressed') !== 'true');
    filtrarHoje();
  });
  // Menu de ordem próprio: botão + lista (mouse, toque e teclado)
  const botaoOrdem = () => document.getElementById('ordem');
  const menuOrdem = () => document.querySelector('.ordem-menu');
  function marcarOrdem(modo) {
    const op = menuOrdem().querySelector('[data-valor="' + modo + '"]');
    menuOrdem().querySelectorAll('[role=option]').forEach((li) => li.setAttribute('aria-selected', li === op));
    botaoOrdem().querySelector('.ordem-valor').textContent = op.querySelector('b').textContent;
  }
  function abrirMenu(abrir) {
    const m = menuOrdem();
    if (m.hidden === !abrir) return;
    m.hidden = !abrir;
    botaoOrdem().setAttribute('aria-expanded', abrir);
    if (abrir) m.querySelector('[aria-selected=true]').focus();
  }
  function escolherOrdem(modo) {
    abrirMenu(false);
    botaoOrdem().focus();
    const o = lerOrdem();
    salvarOrdem({ modo, lista: o.lista?.length ? o.lista : cartoes().map((c) => c.dataset.nome) });
    aplicarOrdem(true);
  }
  document.addEventListener('click', (e) => {
    if (e.target.closest('#ordem')) return abrirMenu(menuOrdem().hidden);
    const li = e.target.closest('.ordem-menu [role=option]');
    if (li) return escolherOrdem(li.dataset.valor);
    if (!e.target.closest('.ordem-menu')) abrirMenu(false); // clique fora fecha
  });
  document.addEventListener('keydown', (e) => {
    const m = menuOrdem();
    if (!m) return;
    if (m.hidden) {
      if (e.target.id === 'ordem' && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) { e.preventDefault(); abrirMenu(true); }
      return;
    }
    const ops = [...m.querySelectorAll('[role=option]')], i = ops.indexOf(document.activeElement);
    if (e.key === 'Escape') { abrirMenu(false); botaoOrdem().focus(); }
    else if (e.key === 'Tab') abrirMenu(false);
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); ops[(i + (e.key === 'ArrowDown' ? 1 : -1) + ops.length) % ops.length].focus(); }
    else if ((e.key === 'Enter' || e.key === ' ') && i >= 0) { e.preventDefault(); escolherOrdem(ops[i].dataset.valor); }
  });
  // Personalizada: arrasta pela alça (mouse ou dedo) ou move com as setas do teclado
  let arrastando = null, pega = null; // pega: onde o dedo segurou o cartão
  // Cartão flutuante: posição da vaga atual + deslocamento até o dedo
  function seguir(x, y) {
    arrastando.style.transform = '';
    const r = arrastando.getBoundingClientRect();
    arrastando.style.transform = 'translate(' + (x - pega.x - r.left) + 'px,' + (y - pega.y - r.top) + 'px) scale(1.03) rotate(-1deg)';
  }
  document.addEventListener('pointerdown', (e) => {
    const h = e.target.closest('.alca');
    if (!h) return;
    e.preventDefault();
    arrastando = h.closest('.card');
    const r = arrastando.getBoundingClientRect();
    pega = { x: e.clientX - r.left, y: e.clientY - r.top };
    arrastando.classList.add('arrastando');
    document.body.classList.add('arrastando');
    cartoes().forEach((c) => c.classList.add('sem-anim')); // mover no DOM reinicia as barras; só o solto anima, ao pousar
    seguir(e.clientX, e.clientY);
  });
  document.addEventListener('pointermove', (e) => {
    if (!arrastando) return;
    const alvo = document.elementFromPoint(e.clientX, e.clientY)?.closest('.grade > .card'); // o flutuante ignora o ponteiro
    if (alvo && alvo !== arrastando && !alvo.getAnimations().some((a) => a.id === 'flip')) { // espera o alvo parar de deslizar
      const lista = cartoes();
      mover(() => lista.indexOf(arrastando) < lista.indexOf(alvo) ? alvo.after(arrastando) : alvo.before(arrastando));
    }
    seguir(e.clientX, e.clientY);
  });
  const soltar = () => {
    if (!arrastando) return;
    const c = arrastando, de = c.style.transform;
    arrastando = null;
    c.style.transform = '';
    document.body.classList.remove('arrastando');
    // Pousa na vaga deslizando a partir de onde foi solto
    const a = c.animate([{ transform: de }, { transform: 'none' }], { duration: 220, easing: 'cubic-bezier(.16,1,.3,1)' });
    a.onfinish = a.oncancel = () => c.classList.remove('arrastando', 'sem-anim');
    salvarPersonalizada();
  };
  document.addEventListener('pointerup', soltar);
  document.addEventListener('pointercancel', soltar);
  document.addEventListener('keydown', (e) => {
    const h = e.target.closest?.('.alca'), passo = { ArrowUp: -1, ArrowLeft: -1, ArrowDown: 1, ArrowRight: 1 }[e.key];
    if (!h || !passo) return;
    e.preventDefault();
    const c = h.closest('.card');
    mover(() => passo < 0 ? c.previousElementSibling?.before(c) : c.nextElementSibling?.after(c));
    h.focus();
    salvarPersonalizada();
  });
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
    if (e.target.closest('.alca, .limpar-sim')) return e.preventDefault(); // alça e "limpar" não abrem o calendário
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
    <div class="titulo">
      <h1>Frequência</h1>
      <p class="sub">Atualizado ${esc(dataBR(atualizadoEm, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }))}${esc(quandoProxima)}</p>
      <div class="ordem">
        <span id="ordem-rotulo">Ordenar por:</span>
        <button type="button" id="ordem" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="ordem-rotulo ordem"><span class="ordem-valor">${OPCOES_ORDEM[0][1]}</span>${SETA_BAIXO}</button>
        <ul class="ordem-menu" role="listbox" aria-labelledby="ordem-rotulo" hidden>
          ${OPCOES_ORDEM.map(([v, t, d]) => `<li role="option" tabindex="-1" data-valor="${v}" aria-selected="${v === 'risco'}"><b>${t}</b><small>${d}</small>${CHECK}</li>`).join('')}
        </ul>
      </div>
      <button type="button" id="so-hoje" aria-pressed="false" title="Mostrar só as matérias com aula hoje">Hoje</button>
      <label class="switch" for="simulador">Simulador<button type="button" id="simulador" role="switch" aria-checked="false" title="Simular faltas e presenças no calendário"></button></label>
    </div>
    ${botao}
  </div>
  ${aviso}
  <section class="grade">${materias.map(cartao).join('')}</section>
  <p class="vazio-hoje" hidden>Sem aulas hoje.</p>
  ${modo === 'web' ? '<p class="rodape">Projeto pessoal, não oficial do Insper. Os dados vêm do Aluno Online com o seu login.</p>' : ''}
</main>
<script>
/*!
 * Lentes de vidro: porte em JS puro da refração da skill liquid-glass (stormaref), que por sua vez porta o shader de
 * liquid-glass-js (https://github.com/dashersw/liquid-glass-js) — Copyright (c) 2025 Armagan Amcalar, MIT.
 * Permission is hereby granted, free of charge, to any person obtaining a copy of that software to deal in it without
 * restriction, provided this notice travels with it; it is provided "as is", without warranty of any kind.
 */
(() => {
  // backdrop-filter com url() só pinta no Chromium; o Safari aceita a regra e não desenha nada, por isso não dá pra usar @supports
  const ua = navigator.userAgentData;
  if (!(ua ? ua.brands.some((b) => /Chrom|Edge/.test(b.brand)) : navigator.userAgent.includes('Chrome/'))) return;
  document.documentElement.classList.add('lente');
  const NS = 'http://www.w3.org/2000/svg';
  const defs = document.createElementNS(NS, 'svg');
  defs.setAttribute('width', 0); defs.setAttribute('height', 0); defs.setAttribute('aria-hidden', 'true');
  defs.style.position = 'absolute';
  document.body.append(defs);
  const BLUR = { topo: 8, versao: 4, card: 6 }; // raio do fosco; vezes 0,35 vira o desvio do gaussiano
  const cache = new Map(); // shortcut: filtros antigos não são apagados; ok pra meia dúzia de tamanhos, refazer com contagem se crescer
  let n = 0;
  const mapa = (w, h, r, pw, ph) => {
    const f = Math.max(.25, Math.min(2, 1400 / Math.max(w, h))), W = Math.ceil(w * f), H = Math.ceil(h * f), m = Math.min(w, h);
    const dx = new Float32Array(W * H), dy = new Float32Array(W * H);
    let max = 0;
    for (let j = 0; j < H; j++) for (let i = 0; i < W; i++) {
      const px = (i + .5) / f, py = (j + .5) / f, cx = px / w, cy = py / h;
      const tx = Math.abs(px - w / 2) - (w / 2 - r), ty = Math.abs(py - h / 2) - (h / 2 - r);
      const d = Math.max(-(Math.hypot(Math.max(tx, 0), Math.max(ty, 0)) + Math.min(Math.max(tx, ty), 0) - r), 0);
      const aro = Math.exp(-d * 1.7), total = Math.exp(-d * .5) * .015 + aro * .028;
      let nx = cx - .5, ny = cy - .5; const l = Math.hypot(nx, ny) || 1; nx /= l; ny /= l;
      const canto = Math.exp(-(Math.max(Math.min(cx, 1 - cx), Math.min(cy, 1 - cy)) * m) * .3) * .06;
      const onda = Math.sin((d / m) * 25) * .26 * aro;
      const k = j * W + i;
      dx[k] = (nx * (total + canto) - ny * onda) * pw; dy[k] = (ny * (total + canto) + nx * onda) * ph;
      max = Math.max(max, Math.abs(dx[k]), Math.abs(dy[k]));
    }
    const escala = Math.max(max * 2, 1e-4), vies = escala * (128 / 255 - .5); // 128 não é zero no feDisplacementMap
    const tela = document.createElement('canvas'); tela.width = W; tela.height = H;
    const ctx = tela.getContext('2d'), img = ctx.createImageData(W, H);
    for (let k = 0; k < W * H; k++) {
      img.data[k * 4] = 255 * (.5 + (dx[k] - vies) / escala); img.data[k * 4 + 1] = 255 * (.5 + (dy[k] - vies) / escala);
      img.data[k * 4 + 2] = 128; img.data[k * 4 + 3] = 255;
    }
    ctx.putImageData(img, 0, 0);
    return { url: tela.toDataURL(), escala };
  };
  const filtro = (w, h, r, blur) => {
    const pw = innerWidth, ph = innerHeight, chave = [w, h, r, pw, ph, blur].join();
    const pronto = cache.get(chave);
    if (pronto?.isConnected) return pronto.id;
    const { url, escala } = mapa(w, h, r, pw, ph), desvio = blur * .35, mg = escala / 2 + 3 * desvio;
    const fl = document.createElementNS(NS, 'filter');
    fl.id = 'lente' + n++;
    Object.entries({ filterUnits: 'userSpaceOnUse', x: -mg, y: -mg, width: w + 2 * mg, height: h + 2 * mg, 'color-interpolation-filters': 'sRGB' }).forEach(([k, v]) => fl.setAttribute(k, v));
    fl.innerHTML = '<feImage href="' + url + '" x="0" y="0" width="' + w + '" height="' + h + '" preserveAspectRatio="none" result="m"/>' +
      '<feDisplacementMap in="SourceGraphic" in2="m" scale="' + escala + '" xChannelSelector="R" yChannelSelector="G"/>' +
      '<feGaussianBlur stdDeviation="' + desvio + '"/>';
    defs.append(fl); cache.set(chave, fl);
    return fl.id;
  };
  const aplicar = (el) => {
    const w = Math.round(el.offsetWidth), h = Math.round(el.offsetHeight);
    if (!w || !h) return;
    const rr = getComputedStyle(el).borderTopLeftRadius, r = Math.min(rr.endsWith('%') ? parseFloat(rr) / 100 * Math.min(w, h) : parseFloat(rr) || 0, Math.min(w, h) / 2);
    const tipo = el.classList.contains('topo') ? 'topo' : el.classList.contains('versao') ? 'versao' : 'card';
    el.style.setProperty('--lente', 'url(#' + filtro(w, h, r, BLUR[tipo]) + ')');
  };
  // Refaz no próximo quadro quando o elemento muda de tamanho (ex.: abrir o calendário) e, com folga, quando a janela muda
  const fila = new Set(); let quadro = 0;
  const agendar = (el) => { fila.add(el); quadro ||= requestAnimationFrame(() => { quadro = 0; fila.forEach(aplicar); fila.clear(); }); };
  const ro = new ResizeObserver((es) => es.forEach((e) => agendar(e.target)));
  const vistos = new WeakSet();
  const varrer = () => document.querySelectorAll('.topo, .versao, .grade > .card').forEach((el) => { if (!vistos.has(el)) { vistos.add(el); ro.observe(el); } });
  varrer();
  new MutationObserver(varrer).observe(document.querySelector('main'), { childList: true, subtree: true }); // cartões novos depois de "Atualizar"
  let espera;
  addEventListener('resize', () => { clearTimeout(espera); espera = setTimeout(() => document.querySelectorAll('.topo, .versao, .grade > .card').forEach(agendar), 180); });
})();
</script>
<div class="versao" role="group" aria-label="Versão do visual"><span class="pilula" aria-hidden="true"></span>
  <button type="button" data-v="original">Original</button><button type="button" data-v="premium">Premium</button>
</div>
<script>
  (() => {
    const caixa = document.querySelector('.versao'), pilula = caixa.querySelector('.pilula'), bs = caixa.querySelectorAll('button');
    const calma = matchMedia('(prefers-reduced-motion: reduce)');
    // Elástico do iOS: quanto mais passa, menos anda (nunca mais que d)
    const elastico = (x, d = 36) => (1 - 1 / (x * .55 / d + 1)) * d;
    const MOLA = 'linear(0, .08 3%, .3 8%, .62 14%, .88 21%, 1.04 28%, 1.09 34%, 1.08 40%, 1.03 50%, .995 62%, .992 72%, 1)';
    const marcar = (animar) => {
      const de = { left: pilula.offsetLeft, width: pilula.offsetWidth };
      let alvo;
      bs.forEach((b) => { const sim = document.documentElement.classList.contains('premium') === (b.dataset.v === 'premium'); b.setAttribute('aria-pressed', sim); if (sim) alvo = b; });
      const para = { left: alvo.offsetLeft, width: alvo.offsetWidth };
      Object.assign(pilula.style, { left: para.left + 'px', width: para.width + 'px' });
      if (!animar || calma.matches || !de.width) return;
      // Estica como gel cobrindo as duas opções no meio do caminho, depois assenta com mola
      const meio = { left: Math.min(de.left, para.left) + 4, width: Math.abs(para.left - de.left) + Math.min(de.width, para.width) - 8 };
      const quadros = [{ left: de.left + 'px', width: de.width + 'px' }, { left: para.left + 'px', width: para.width + 'px' }];
      if (Math.abs(para.left - de.left) > 12) quadros.splice(1, 0, { left: meio.left + 'px', width: meio.width + 'px', offset: .35 });
      pilula.animate(quadros, { duration: 650, easing: MOLA });
    };
        // A lente fica enquanto o dedo segura e some ao soltar (um mínimo de 180 ms pra aparecer num toque rápido)
    let desde = 0;
    const segurar = (el, classe) => el.addEventListener('pointerdown', () => {
      desde = Date.now(); el.classList.add(classe);
      const fim = () => { setTimeout(() => el.classList.remove(classe), Math.max(0, 180 - (Date.now() - desde))); removeEventListener('pointerup', fim); removeEventListener('pointercancel', fim); };
      addEventListener('pointerup', fim); addEventListener('pointercancel', fim);
    });
    segurar(caixa, 'apertando');
    const sim = document.querySelector('#simulador');
    if (sim) {
      segurar(sim, 'apertado');
      // Arrastar a bolinha do switch; ao soltar, liga se passou da metade
      let a = null, ignorar = false;
      sim.addEventListener('pointerdown', (e) => { a = { x: e.clientX, base: sim.getAttribute('aria-checked') === 'true' ? 16 : 0, moveu: false, v: 0, ux: e.clientX, ut: e.timeStamp }; sim.setPointerCapture(e.pointerId); });
      sim.addEventListener('pointermove', (e) => {
        if (!a) return;
        const dx = e.clientX - a.x;
        if (Math.abs(dx) > 3) { a.moveu = true; sim.classList.add('arrastando'); }
        if (!a.moveu) return;
        a.v = (e.clientX - a.ux) / Math.max(1, e.timeStamp - a.ut); a.ux = e.clientX; a.ut = e.timeStamp;
        const x = a.base + dx, sobra = x > 16 ? elastico(x - 16, 14) : x < 0 ? elastico(-x, 14) : 0;
        sim.style.setProperty('--kx', (x > 16 ? 16 : x < 0 ? -sobra : x) + 'px');
        sim.style.setProperty('--kw', sobra + 'px');
      });
      const fim = (valer) => {
        if (!a) return;
        const { moveu, v: a_v } = a; a = null;
        if (!moveu) return;
        const kx = parseFloat(sim.style.getPropertyValue('--kx')) + a_v * 100; // inércia
        sim.classList.remove('arrastando'); sim.style.removeProperty('--kx'); sim.style.removeProperty('--kw');
        ignorar = true; setTimeout(() => ignorar = false, 300); // o clique que vem depois do arrasto não alterna de novo
        if (valer && (kx > 8) !== (sim.getAttribute('aria-checked') === 'true')) ligarSimulador(kx > 8);
      };
      sim.addEventListener('pointerup', () => fim(true));
      sim.addEventListener('pointercancel', () => fim(false));
      sim.addEventListener('click', (e) => { if (ignorar) { ignorar = false; e.stopImmediatePropagation(); e.preventDefault(); } });
    }
    const escolher = (v) => {
      document.documentElement.classList.toggle('premium', v === 'premium');
      try { localStorage.versao = v; } catch {}
      marcar(true);
    };
    let arrasto = null;
    bs.forEach((b) => b.onclick = (e) => { if (e.detail === 0) escolher(b.dataset.v); }); // teclado; o toque é tratado no largar
    // Arrastar a pílula de uma opção pra outra; ao soltar, fica na opção mais perto do centro dela
    caixa.addEventListener('pointerdown', (e) => {
      arrasto = { x: e.clientX, left: pilula.offsetLeft, w: pilula.offsetWidth, moveu: false, botao: e.target.closest('button'), v: 0, ux: e.clientX, ut: e.timeStamp };
      caixa.setPointerCapture(e.pointerId);
    });
    caixa.addEventListener('pointermove', (e) => {
      if (!arrasto) return;
      const dx = e.clientX - arrasto.x;
      if (Math.abs(dx) > 3) arrasto.moveu = true;
      if (!arrasto.moveu) return;
      arrasto.v = (e.clientX - arrasto.ux) / Math.max(1, e.timeStamp - arrasto.ut); arrasto.ux = e.clientX; arrasto.ut = e.timeStamp;
      // Passou da ponta: continua um pouco esticando, cada vez mais devagar, como líquido
      const max = caixa.clientWidth - arrasto.w - 3, x = arrasto.left + dx;
      const sobra = x > max ? elastico(x - max) : x < 3 ? elastico(3 - x) : 0;
      pilula.style.left = (x > max ? max : x < 3 ? 3 - sobra : x) + 'px';
      pilula.style.width = arrasto.w + sobra + 'px';
    });
    const largar = () => {
      if (!arrasto) return;
      const { moveu, botao, v: arrasto_v } = arrasto; arrasto = null;
      if (!moveu) return botao && escolher(botao.dataset.v); // toque simples (com captura do ponteiro, o clique não chega no botão)
      const centro = pilula.offsetLeft + pilula.offsetWidth / 2 + arrasto_v * 120; // inércia: um gesto rápido escolhe pra onde ia
      const perto = [...bs].sort((p, q) => Math.abs(p.offsetLeft + p.offsetWidth / 2 - centro) - Math.abs(q.offsetLeft + q.offsetWidth / 2 - centro))[0];
      escolher(perto.dataset.v);
    };
    caixa.addEventListener('pointerup', largar);
    caixa.addEventListener('pointercancel', () => { if (arrasto) { arrasto = null; marcar(true); } }); // volta pro lugar
    marcar(false);
    // Luz do toque: o botão acende a partir do ponto onde o dedo encostou
    document.addEventListener('pointerdown', (e) => {
      const b = e.target.closest?.('#ordem, #so-hoje, #atualizar');
      if (!b) return;
      const r = b.getBoundingClientRect();
      b.style.setProperty('--gx', (e.clientX - r.left) + 'px'); b.style.setProperty('--gy', (e.clientY - r.top) + 'px');
    });
  })();
</script>
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
