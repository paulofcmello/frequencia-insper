# Frequência Insper

Página com, pra cada matéria: aulas restantes, presenças, faltas e quanto ainda dá pra faltar.
Os dados vêm do Aluno Online (sga.insper.edu.br).

**Pra usar:** https://frequencia-insper.vercel.app, com o mesmo login e senha do Aluno Online.
A senha não fica guardada no servidor (veja `api/index.mjs`). Projeto pessoal, não oficial do Insper.

- `api/index.mjs`: site multiusuário na Vercel (login, sessão e "manter conectado" em cookies criptografados).
  Precisa da variável de ambiente `SEGREDO`.
- `faltas-insper.mjs`: faz login, busca frequência e calendário e gera a página.
  - `--github`: modo GitHub Actions, publica no GitHub Pages
  - `--servidor`: servidor local em http://frequencia.localhost:4870
- `.github/workflows/atualizar.yml`: roda 30 min depois de cada aula e às 21h nos dias com aula.
  Também dá pra rodar na hora pelo botão "Atualizar agora" da página.
- `contador-faltas.js` / `favorito-faltas.html`: versão bookmarklet, roda dentro do portal logado.
- `compartilhar/`: instalador pra usar no Mac de outra pessoa.

Secrets do repositório: `INSPER_LOGIN` e `INSPER_SENHA`.
