# Frequência Insper

Página com, pra cada matéria: aulas restantes, presenças, faltas e quanto ainda dá pra faltar.
Os dados vêm do Aluno Online (sga.insper.edu.br).

- `faltas-insper.mjs`: faz login, busca frequência e calendário e gera a página.
  - `--github`: modo GitHub Actions, publica no GitHub Pages
  - `--servidor`: servidor local em http://frequencia.localhost:4870
- `.github/workflows/atualizar.yml`: roda 30 min depois de cada aula e às 21h nos dias com aula.
  Também dá pra rodar na hora pelo botão "Atualizar agora" da página.
- `contador-faltas.js` / `favorito-faltas.html`: versão bookmarklet, roda dentro do portal logado.
- `compartilhar/`: instalador pra usar no Mac de outra pessoa.

Secrets do repositório: `INSPER_LOGIN` e `INSPER_SENHA`.
