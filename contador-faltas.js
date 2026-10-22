// Contador de faltas — Insper Aluno Online (Lyceum)
// Roda dentro de https://sga.insper.edu.br/AOnline/ com a sessão logada.
(async () => {
  const BASE = '/AOnline/apix';
  const PANEL_ID = 'contador-faltas-panel';
  // Último dia de aula de cada semestre ("ano-semestre" do portal); depois vêm as provas
  const ULTIMO_DIA_DE_AULA = { '2026-62': '2026-11-25' };
  // Horários que a agenda do portal mostra trocados (dia: 0 = domingo)
  const CORRECOES_DE_HORARIO = [
    { de: 'ROBCOMP_3ENGCOMA', para: 'DESCMAT_3ENGCOMA', dia: 2, hora: '16:30' },
    { de: 'DESCMAT_3ENGCOMA', para: 'ROBCOMP_3ENGCOMA', dia: 4, hora: '16:30' },
  ];

  document.getElementById(PANEL_ID)?.remove();

  const getJSON = async (url) => {
    const r = await fetch(BASE + url, { credentials: 'include' });
    if (!r.ok) throw new Error(r.status + ' em ' + url);
    return r.json();
  };

  const panel = document.createElement('div');
  panel.id = PANEL_ID;
  panel.style.cssText = [
    'position:fixed', 'top:16px', 'right:16px', 'z-index:2147483647',
    'width:min(380px,calc(100vw - 32px))', 'max-height:calc(100vh - 32px)', 'overflow:auto',
    'background:#fff', 'color:#1a1a1a', 'border-radius:12px',
    'box-shadow:0 8px 32px rgba(0,0,0,.25)', 'font:14px/1.4 system-ui,-apple-system,sans-serif',
    'padding:16px',
  ].join(';');
  panel.innerHTML =
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">' +
    '<strong style="font-size:16px">Frequência</strong>' +
    '<button id="' + PANEL_ID + '-close" style="border:0;background:none;font-size:20px;cursor:pointer;color:#666" aria-label="Fechar">×</button>' +
    '</div><div id="' + PANEL_ID + '-body">Carregando…</div>';
  document.body.appendChild(panel);
  panel.querySelector('#' + PANEL_ID + '-close').onclick = () => panel.remove();
  const body = panel.querySelector('#' + PANEL_ID + '-body');

  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  // Mensagens vão no painel, não em alert(): alguns navegadores descartam alerts em silêncio
  if (location.hostname !== 'sga.insper.edu.br') {
    body.innerHTML = 'Abra o <a href="https://sga.insper.edu.br/AOnline/#/home/frequencia">Aluno Online</a>, faça login e clique no favorito de novo.';
    return;
  }

  let aluno;
  try {
    const a = JSON.parse(JSON.parse(sessionStorage.getItem('ngStorage-_a')));
    aluno = a.list[a.selecionado || 0];
  } catch (e) {}
  if (!aluno?.codAluno || !aluno?.id) {
    body.textContent = 'Não achei sua sessão. Faça login no Aluno Online e clique no favorito de novo.';
    return;
  }
  const codAluno = aluno.codAluno;
  const codPessoa = aluno.id;

  try {
    const resumo = await getJSON(
      '/api/rest/alunos/codAluno/' + codAluno + '/codPessoa/' + codPessoa + '/Frequencias?page=0&size=1000'
    );
    // A agenda do portal lista cada aula do semestre (feriados já excluídos).
    // Ela só devolve um mês por consulta, então busca de 6 meses atrás a 6 meses à frente.
    const hoje = new Date();
    const meses = [];
    for (let i = -6; i <= 6; i++) meses.push(new Date(hoje.getFullYear(), hoje.getMonth() + i, 1));
    const isoDia = (dt) =>
      dt.getFullYear() + '-' + String(dt.getMonth() + 1).padStart(2, '0') + '-' + String(dt.getDate()).padStart(2, '0');
    const eventos = (
      await Promise.all(
        meses.map((ini) => {
          const fim = new Date(ini.getFullYear(), ini.getMonth() + 1, 1);
          return getJSON(
            '/api/rest/alunos/pessoa/' + codPessoa + '/events?codAluno=' + codAluno +
              '&start=' + isoDia(ini) + 'T00:00:00.000-03:00&end=' + isoDia(fim) + 'T00:00:00.000-03:00' +
              '&page=0&size=2000&timezone=false'
          ).then((j) => j.content || j || [], () => []);
        })
      )
    ).flat();
    const aulasPorTurma = {};
    const vistos = new Set();
    for (const ev of eventos) {
      if (ev.tipoEvento !== 'AULA' || vistos.has(ev.eventId)) continue;
      vistos.add(ev.eventId);
      let turma = (String(ev.descricao).match(/Turma: (\S+)/) || [])[1];
      const dia = new Date(String(ev.startStr).slice(0, 10) + 'T12:00:00Z').getUTCDay();
      const hora = String(ev.startStr).slice(11, 16);
      const regra = CORRECOES_DE_HORARIO.find((r) => r.de === turma && r.dia === dia && r.hora === hora);
      if (regra) turma = regra.para;
      if (turma) (aulasPorTurma[turma] = aulasPorTurma[turma] || []).push(ev);
    }

    const materias = await Promise.all(
      (resumo.content || []).map(async (m) => {
        const d = await getJSON(
          '/v2/alunos/' + codAluno + '/detalhes-faltas?ano=' + m.ano + '&semestre=' + m.semestre +
            '&codDisciplina=' + encodeURIComponent(m.codDisciplina) + '&codTurma=' + encodeURIComponent(m.codigoTurma)
        );
        const nivel = (d.detalhesFrequenciaPorNivel || [])[0] || {};
        const datas = (d.faltasDiarias || []).map((f) => f.data);
        const faltas = nivel.faltasAcumuladas ?? d.totalFaltas ?? datas.length;

        // Depois do último dia de aula vêm as provas, que não contam presença
        const ultimoDia = ULTIMO_DIA_DE_AULA[m.ano + '-' + m.semestre];
        const limite = ultimoDia ? new Date(ultimoDia + 'T23:59:59-03:00').getTime() : Infinity;
        const aulas = (aulasPorTurma[m.codigoTurma] || []).filter((a) => a.startDate <= limite);
        // O portal conta aulas e faltas permitidas em horas; cada encontro vale a duração dele (2h)
        const horasPorAula = aulas.length ? Math.round((aulas[0].endDate - aulas[0].startDate) / 3600000) || 1 : 2;
        const previstasPortal = nivel.aulasPrevistas ?? m.aulasPrevistas;
        const permitidas = Math.floor((nivel.faltasPermitidas ?? previstasPortal * 0.25) / horasPorAula);

        const total = aulas.length || Math.round(previstasPortal / horasPorAula);
        const dadas = aulas.length
          ? aulas.filter((a) => a.endDate <= hoje.getTime()).length
          : Math.round((nivel.aulasMinistradas ?? m.cargaHoraria) / horasPorAula);
        return {
          nome: m.componenteCurricular.trim(),
          faltas,
          permitidas,
          restantes: permitidas - faltas,
          presencas: dadas - faltas,
          presencasNecessarias: total - permitidas,
          aulasRestantes: total - dadas,
          ministradas: dadas,
          previstas: total,
          ultimaAula: aulas.length ? new Date(Math.max(...aulas.map((a) => a.startDate))).toLocaleDateString('pt-BR') : null,
          datas,
        };
      })
    );

    if (!materias.length) {
      body.textContent = 'Nenhuma matéria encontrada neste semestre.';
      return;
    }

    const linha = (rotulo, valor, total, cor, nota) =>
      '<div style="margin-top:8px">' +
      '<div style="display:flex;justify-content:space-between;font-size:13px">' +
      '<span>' + rotulo + ' <strong>' + valor + '/' + total + '</strong></span>' +
      '<span style="color:' + cor + '">' + nota + '</span></div>' +
      '<div style="height:6px;background:#eee;border-radius:3px;margin-top:4px;overflow:hidden">' +
      '<div style="height:100%;width:' + (total > 0 ? Math.min(1, Math.max(0, valor / total)) * 100 : 0) + '%;background:' + cor + '"></div></div>' +
      '</div>';

    // Fração das aulas restantes em que ainda dá pra faltar; define a ordem e a cor
    const folga = (m) =>
      m.restantes < 0 ? -1 : m.aulasRestantes <= 0 ? 1 : Math.min(m.restantes, m.aulasRestantes) / m.aulasRestantes;
    materias.sort((a, b) => folga(a) - folga(b) || a.restantes - b.restantes);
    body.innerHTML = materias
      .map((m) => {
        const f = folga(m);
        const corFaltas = m.restantes <= 0 || f < 0.25 ? '#c62828' : f < 0.5 ? '#ef6c00' : '#2e7d32';
        const podeFaltar = Math.min(m.restantes, m.aulasRestantes);
        const pct = m.aulasRestantes > 0 ? Math.round((podeFaltar / m.aulasRestantes) * 100) : 0;
        const notaFaltas = m.restantes < 0
          ? 'passou ' + -m.restantes + ' do limite'
          : m.restantes === 0
            ? 'não pode mais faltar'
            : 'pode faltar ' + podeFaltar + '/' + m.aulasRestantes + ' restantes (' + pct + '%)';

        const faltamPresencas = Math.max(0, m.presencasNecessarias - m.presencas);
        const notaPresencas = faltamPresencas === 0
          ? 'presença garantida'
          : 'faltam ' + faltamPresencas + ' de ' + m.aulasRestantes + ' aulas';
        const corPresencas = faltamPresencas === 0 ? '#2e7d32' : faltamPresencas > m.aulasRestantes ? '#c62828' : '#1565c0';

        const ultimas = m.datas.slice(-3).join(', ');
        return (
          '<div style="padding:10px 0;border-top:1px solid #eee">' +
          '<div style="font-weight:600">' + esc(m.nome) + '</div>' +
          '<div style="font-size:13px;margin-top:2px">Restam <strong>' + m.aulasRestantes + ' aulas</strong> no total' +
          (m.ultimaAula ? ' (até ' + m.ultimaAula + ')' : '') + '</div>' +
          linha('Presenças', m.presencas, m.presencasNecessarias, corPresencas, notaPresencas) +
          linha('Faltas', m.faltas, m.permitidas, corFaltas, notaFaltas) +
          '<div style="font-size:12px;color:#777;margin-top:6px">Aulas dadas: ' + m.ministradas + ' de ' + m.previstas +
          (ultimas ? '<br>Últimas faltas: ' + esc(ultimas) : '') + '</div>' +
          '</div>'
        );
      })
      .join('');
  } catch (e) {
    body.innerHTML = 'Erro ao buscar as faltas (' + esc(e.message) + '). Sua sessão pode ter expirado: faça login de novo.';
  }
})();
