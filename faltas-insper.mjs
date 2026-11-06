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
      const dica = faltas.has(iso) ? 'Falta' : feriados[iso] ? 'Feriado: ' + feriados[iso] : aulas[iso] ? 'Aula ' + aulas[iso].join(', ') + (tipo === 'aula' ? ' · toque pra simular falta' : '') : '';
      const classe = `class="${tipo}${iso === hoje ? ' hoje' : ''}"${dica ? ` title="${esc(dica)}"` : ''}`;
      // Aula futura é botão: toque marca/desmarca uma falta simulada
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
    <div class="legenda"><span class="aula">aula</span><span class="foi">presença</span><span class="falta">falta</span><span class="feriado">feriado</span><span class="hoje">hoje</span><span class="plano">falta simulada</span></div>
    <div class="cal-dica">Toque numa aula futura pra simular uma falta.</div>
    ${listaFeriados ? '<div class="cal-feriados">Feriados sem aula: ' + listaFeriados + '</div>' : ''}`;
}

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
      <b class="hero-titulo">${heroTitulo}</b>
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
          --bom:#248a3d; --medio:#c93400; --ruim:#d70015; --pres:#0a63c9; --borda:#e5e5ea; --on:#fff; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#000; --card:#1c1c1e; --txt:#f5f5f7; --sub:#98989d; --trilho:#3a3a3c;
            --bom:#30d158; --medio:#ff9f0a; --ruim:#ff453a; --pres:#409cff; --borda:#2c2c2e; --on:#000; }
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
  .barra.falt { background:var(--nivel); }
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
  /* Painel das próximas aulas */
  .hoje { display:flex; align-items:center; gap:10px 16px; flex-wrap:wrap; margin:0 0 14px; }
  .hoje[hidden] { display:none; }
  .hoje-cab { display:flex; flex-direction:column; line-height:1.25; }
  .hoje-cab b { font-size:16px; letter-spacing:-.01em; }
  .hoje-resumo { font-size:12.5px; font-weight:500; } .hoje-resumo.ok { color:var(--bom); } .hoje-resumo.nao { color:var(--ruim); }
  .hoje-lista { display:flex; gap:8px; flex-wrap:wrap; }
  .aula-hoje { --nivel:var(--bom); display:grid; grid-template-columns:auto auto; column-gap:12px; align-items:baseline; text-align:left;
               font:inherit; color:var(--txt); background:var(--card); border:1px solid var(--borda); border-radius:12px; padding:7px 12px;
               cursor:pointer; transition:border-color .15s, background-color .15s; }
  .aula-hoje.medio { --nivel:var(--medio); } .aula-hoje.ruim { --nivel:var(--ruim); }
  .aula-hoje:hover { border-color:var(--nivel); }
  .aula-hoje:focus-visible { outline:2px solid var(--pres); outline-offset:2px; }
  .aula-hoje .hora { grid-row:span 2; font-size:15px; font-weight:700; letter-spacing:-.01em; }
  .aula-hoje .agora { display:block; font-size:10px; font-weight:600; color:var(--pres); text-transform:uppercase; letter-spacing:.04em; }
  .aula-hoje .mat { font-size:13px; font-weight:500; }
  .aula-hoje .ver { font-size:12px; font-weight:600; color:var(--nivel); }
  .aula-hoje.plano { border-color:var(--ruim); background:color-mix(in srgb, var(--ruim) 8%, var(--card)); }
  .aula-hoje.plano .ver { color:var(--ruim); }
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
    montarHoje();
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
      if (c === arrastando) continue; // esse segue o dedo, não desliza
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
  document.addEventListener('DOMContentLoaded', () => { aplicarOrdem(false); aplicarSim(); montarHoje(); setInterval(montarHoje, 60 * 1000); });

  // Simulador: faltas planejadas em aulas futuras, guardadas só neste navegador
  const CHAVE_SIM = 'frequencia-simulacao';
  const hojeSP = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' });
  const agoraSP = () => new Date().toLocaleTimeString('sv-SE', { timeZone: 'America/Sao_Paulo', hour: '2-digit', minute: '2-digit' });
  const lerSim = () => { try { return JSON.parse(localStorage.getItem(CHAVE_SIM)) || {}; } catch { return {}; } };
  const salvarSim = () => {
    const sim = {};
    for (const c of cartoes()) {
      const dias = [...c.querySelectorAll('.cal button.plano')].map((b) => b.dataset.dia);
      if (dias.length) sim[c.dataset.nome] = dias;
    }
    try { localStorage.setItem(CHAVE_SIM, JSON.stringify(sim)); } catch {}
  };
  function aplicarSim() {
    const sim = lerSim(), hoje = hojeSP();
    for (const c of cartoes()) {
      const dias = new Set((sim[c.dataset.nome] || []).filter((d) => d >= hoje)); // dia que passou não conta mais
      c.querySelectorAll('.cal button[data-dia]').forEach((b) => marcarPlano(b, dias.has(b.dataset.dia)));
      simular(c);
    }
  }
  function marcarPlano(b, sim) { b.classList.toggle('plano', sim); b.setAttribute('aria-pressed', sim); }
  // Mesma conta do servidor (cartao/folga), com as faltas simuladas somadas
  function simular(c) {
    const hoje = hojeSP();
    const k = [...c.querySelectorAll('.cal button.plano')].filter((b) => b.dataset.dia >= hoje).reduce((t, b) => t + +b.dataset.n, 0);
    const R = c.dataset.restantes - k, A = +c.dataset.aulasRestantes, F = +c.dataset.faltas + k, P = +c.dataset.permitidas;
    const pode = Math.max(0, Math.min(R, A)), pct = A > 0 ? Math.round((pode / A) * 100) : 0;
    const f = R < 0 ? -1 : A <= 0 ? 1 : Math.min(R, A) / A;
    const nivel = R <= 0 || f < 0.25 ? 'ruim' : f < 0.5 ? 'medio' : 'bom';
    c.classList.remove('bom', 'medio', 'ruim');
    c.classList.add(nivel);
    c.dataset.podeAgora = pode;
    c.dataset.nivelAgora = nivel;
    const big = c.querySelector('.big');
    if (big && A > 0) {
      const [tit, num, sub] = R < 0
        ? ['Passou do limite', '+' + -R, -R === 1 ? 'falta a mais' : 'faltas a mais']
        : [R === 0 ? 'Não pode mais faltar' : 'Pode faltar', pode, 'de ' + A + (A === 1 ? ' aula restante' : ' aulas restantes') + (R > 0 ? ' · ' + pct + '%' : '')];
      c.querySelector('.hero-titulo').textContent = tit;
      big.textContent = num;
      c.querySelector('.hero-sub').textContent = sub;
    }
    const planejados = Math.min(k, A - pode);
    c.querySelectorAll('.blocos i').forEach((b, j) => { b.classList.toggle('livre', j < pode); b.classList.toggle('plano', j >= pode && j < pode + planejados); });
    const v = c.querySelector('.stats > div:nth-child(2) .v');
    v.firstChild.textContent = F;
    c.querySelector('.barra.falt').style.width = (P > 0 ? Math.min(100, (F / P) * 100) : 0).toFixed(1) + '%';
    const aviso = c.querySelector('.sim');
    aviso.hidden = k === 0;
    aviso.querySelector('b').textContent = k === 1 ? '1 falta' : k + ' faltas';
  }
  document.addEventListener('click', (e) => {
    const b = e.target.closest('.cal button[data-dia]');
    const limpar = e.target.closest('.limpar-sim');
    if (!b && !limpar) return;
    e.preventDefault(); // "limpar" fica dentro do <summary>: não abre/fecha o calendário
    const c = (b || limpar).closest('.card');
    if (b) marcarPlano(b, !b.classList.contains('plano'));
    else c.querySelectorAll('.cal button.plano').forEach((x) => marcarPlano(x, false));
    simular(c);
    salvarSim();
    montarHoje();
  });

  // Painel "Hoje": próximas aulas do dia (ou do próximo dia com aula) e se dá pra faltar
  function montarHoje() {
    const painel = document.querySelector('.hoje');
    if (!painel) return;
    const hoje = hojeSP(), agora = agoraSP();
    const minutos = (h) => +h.slice(0, 2) * 60 + +h.slice(3, 5);
    const aulas = cartoes().flatMap((c) => JSON.parse(c.dataset.aulas || '[]').map((d) => ({ dia: d.slice(0, 10), hora: d.slice(11, 16), c })))
      .filter((a) => a.dia > hoje || (a.dia === hoje && minutos(a.hora) + 100 > minutos(agora))) // aula de 1h40 ainda em andamento conta
      .sort((a, b) => (a.dia + a.hora).localeCompare(b.dia + b.hora));
    if (!aulas.length) { painel.hidden = true; return; }
    const dia = aulas[0].dia, doDia = aulas.filter((a) => a.dia === dia);
    const amanha = new Date(Date.parse(hoje + 'T12:00:00Z') + 864e5).toISOString().slice(0, 10);
    const dataCurta = new Date(dia + 'T12:00:00Z').toLocaleDateString('pt-BR', { weekday: 'short', day: '2-digit', month: '2-digit', timeZone: 'UTC' }).replace('.', '');
    // Dá pra faltar o dia todo se cada matéria tem faltas livres pra todas as aulas dela nesse dia
    const precisa = new Map();
    for (const a of doDia) if (!botaoDoDia(a)?.classList.contains('plano')) precisa.set(a.c, (precisa.get(a.c) || 0) + 1);
    const diaTodo = [...precisa].every(([c, n]) => +c.dataset.podeAgora >= n);
    const el = (tag, cls, txt) => { const x = document.createElement(tag); if (cls) x.className = cls; if (txt != null) x.textContent = txt; return x; };
    const cab = el('div', 'hoje-cab');
    cab.append(el('b', null, dia === hoje ? 'Hoje' : dia === amanha ? 'Amanhã' : 'Próximas aulas'),
      el('span', 'hoje-resumo ' + (diaTodo ? 'ok' : 'nao'), dataCurta + ' · ' + (precisa.size === 0 ? 'todas simuladas' : diaTodo ? 'dá pra faltar o dia todo' : 'não dá pra faltar tudo')));
    const lista = el('div', 'hoje-lista');
    for (const a of doDia) {
      const plano = botaoDoDia(a)?.classList.contains('plano'), pode = +a.c.dataset.podeAgora;
      const item = el('button', 'aula-hoje ' + a.c.dataset.nivelAgora + (plano ? ' plano' : ''));
      item.type = 'button';
      item.title = plano ? 'Tirar a falta simulada' : 'Simular falta nessa aula';
      item.setAttribute('aria-pressed', !!plano);
      const hora = el('span', 'hora', a.hora);
      if (dia === hoje && minutos(a.hora) <= minutos(agora)) hora.append(el('small', 'agora', 'agora'));
      item.append(hora, el('span', 'mat', a.c.querySelector('h2').textContent),
        el('span', 'ver', plano ? 'falta simulada' : pode > 0 ? 'pode faltar · sobram ' + pode : 'não falte'));
      item.onclick = () => botaoDoDia(a)?.click();
      lista.append(item);
    }
    painel.replaceChildren(cab, lista);
    painel.hidden = false;
  }
  const botaoDoDia = (a) => a.c.querySelector('.cal button[data-dia="' + a.dia + '"]');
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
    a.onfinish = a.oncancel = () => c.classList.remove('arrastando');
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
    </div>
    ${botao}
  </div>
  ${aviso}
  <section class="hoje" aria-label="Próximas aulas" hidden></section>
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
