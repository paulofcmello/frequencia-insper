# Frequência Insper

Contador de presenças/faltas por matéria a partir do Aluno Online do Insper (Lyceum, `sga.insper.edu.br/AOnline`).
Mostra: aulas restantes, presenças X/Y, faltas X/limite e "pode faltar N/restantes (%)". Textos da UI em português.

## Três versões, mesmo núcleo (`faltas-insper.mjs`)

| Versão | Onde | Credenciais |
|---|---|---|
| Site multiusuário | https://frequencia-insper.vercel.app (`api/index.mjs`) | cada pessoa digita a própria; servidor não guarda senha |
| Página do Paulo | https://paulofcmello.github.io/frequencia-insper/ (`.github/workflows/atualizar.yml`, modo `--github`) | Secrets `INSPER_LOGIN` / `INSPER_SENHA` |
| Favorito (bookmarklet) | `contador-faltas.js` → `bookmarklet.txt` / `favorito-faltas.html` | roda dentro do portal logado |

Também existem: modo `--servidor` (servidor local em `frequencia.localhost:4870`, desativado) e `compartilhar/` (instalador pro Mac de outra pessoa).

## Fluxo de deploy

- `git push` na `main` → Vercel publica sozinha (Git conectado). Projeto Vercel: `pfc18/frequencia-insper`, env `SEGREDO`.
- GitHub Pages só muda quando o workflow roda (agendado depois das aulas, ou `gh workflow run atualizar.yml -R paulofcmello/frequencia-insper`).
- Ao mudar `contador-faltas.js`, regerar `bookmarklet.txt` e `favorito-faltas.html` (tira linhas `//`, junta com espaço, `encodeURIComponent`).
- Ao mudar lógica de cálculo, mudar nos dois: `faltas-insper.mjs` e `contador-faltas.js`.

## APIs do portal (todas sob `/AOnline/apix`, autenticadas por cookie)

- Login: `POST /AOnline/auth` form `username`, `password` (RSA PKCS#1 v1.5 com `config-properties/public-key`, base64), `recaptchaResponse=''`. Cookie `user-data` (base64 JSON) tem `id` = codPessoa; `api/rest/alunos/user/{id}` dá `codAluno`.
- Resumo: `api/rest/alunos/codAluno/{a}/codPessoa/{p}/Frequencias`
- Detalhe: `v2/alunos/{a}/detalhes-faltas?ano&semestre&codDisciplina&codTurma` → `faltasPermitidas`, `faltasAcumuladas`, `faltasDiarias`
- Agenda: `api/rest/alunos/pessoa/{p}/events?codAluno&start&end` — um mês por consulta; `tipoEvento` AULA/FERIADO/RECESSO; feriados já excluídos.

## Pegadinhas já resolvidas (não desfazer)

- Portal conta aulas e faltas permitidas **em horas** (aula = 2h): limite = `faltasPermitidas / duração da aula`. Limite real: 10 por matéria, 14 em Matemática.
- `percentualFrequencia` do portal vem sempre 100 — ignorar.
- Firewall (Akamai) barra `POST /auth` de servidores sem cabeçalhos de navegador → `Sessao.req` manda User-Agent/Origin/Referer de Safari. "Access Denied" ≠ senha errada; só senha errada pausa as tentativas automáticas.
- `ULTIMO_DIA_DE_AULA` (`'2026-62': '2026-11-25'`): depois disso são provas, não contam. Atualizar a cada semestre.
- `CORRECOES_DE_HORARIO`: a agenda troca terça 16:30 (é Desconstruindo) e quinta 16:30 (é Robótica) — turmas `_3ENGCOMA` do Paulo.
- Atividades complementares (`codDisciplina` `GRAD_AC_…` / nome "AC - ") são ignoradas.
- Ordenação e cor pela fração das aulas restantes que ainda dá pra faltar (`folga`).

## Privacidade

- Nunca commitar `frequencia-dados.json`, `frequencia.html`, `atualizacao.log`, `site/` (no `.gitignore`).
- Commits com e-mail noreply do GitHub (`233840633+paulofcmello@users.noreply.github.com`).
- Site da Vercel: sessão e "manter conectado" só em cookies HttpOnly criptografados (AES-256-GCM com `SEGREDO`); nada de senha em log ou banco.

## Testar

- `node faltas-insper.mjs` — atualiza local (usa Keychain `insper-aonline`).
- `TZ=America/Sao_Paulo FORCAR=true node faltas-insper.mjs --github` — gera `site/` (apagar depois).
- Site: importar `api/index.mjs` num `http.createServer` local com `SEGREDO` qualquer.
