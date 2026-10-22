#!/bin/bash
# Instala o contador de frequência do Insper neste Mac.
# Guarda seu login no Keychain, copia o script pra ~/Frequencia Insper
# e deixa um servidor local em http://frequencia.localhost:4870 que atualiza depois de cada aula.
set -euo pipefail
cd "$(dirname "$0")"

DEST="$HOME/Frequencia Insper"
LABEL="com.frequencia-insper"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PORTA=4870

echo "== Contador de frequência Insper =="
echo

NODE="$(command -v node || true)"
for c in /opt/homebrew/bin/node /usr/local/bin/node; do
  if [ -z "$NODE" ] && [ -x "$c" ]; then NODE="$c"; fi
done
if [ -z "$NODE" ]; then
  echo "Precisa do Node.js. Vou abrir o site: baixe a versão LTS, instale e rode este instalador de novo."
  open https://nodejs.org
  exit 1
fi
MAJOR="$("$NODE" -p 'process.versions.node.split(".")[0]')"
if [ "$MAJOR" -lt 20 ]; then
  echo "Seu Node.js é a versão $MAJOR; precisa da 20 ou mais nova (https://nodejs.org)."
  exit 1
fi

echo "Qual é o seu login do Aluno Online (sga.insper.edu.br)?"
read -r -p "Login: " LOGIN
if [ -z "$LOGIN" ]; then echo "Login vazio, cancelando."; exit 1; fi
echo
echo "Agora digite a senha do Aluno Online (duas vezes). Ela não aparece na tela"
echo "e fica guardada só no Keychain deste Mac."
security add-generic-password -U -s insper-aonline -a "$LOGIN" -w

mkdir -p "$DEST"
cp faltas-insper.mjs "$DEST/"

echo
echo "Testando o login..."
if ! "$NODE" "$DEST/faltas-insper.mjs"; then
  echo
  echo "Não funcionou. Confira login e senha e rode o instalador de novo."
  exit 1
fi

mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NODE</string>
    <string>$DEST/faltas-insper.mjs</string>
    <string>--servidor</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$DEST</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$DEST/atualizacao.log</string>
  <key>StandardErrorPath</key>
  <string>$DEST/atualizacao.log</string>
</dict>
</plist>
EOF
plutil -lint "$PLIST" >/dev/null

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"

for _ in $(seq 1 20); do
  curl -s -o /dev/null "http://127.0.0.1:$PORTA/" && break
  sleep 0.5
done

echo
echo "Pronto! Abrindo http://frequencia.localhost:$PORTA no Safari. Salve nos favoritos."
open -a Safari "http://frequencia.localhost:$PORTA"
