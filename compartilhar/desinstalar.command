#!/bin/bash
# Remove o contador de frequência do Insper: para o servidor, apaga o agendamento e o login do Keychain.
LABEL="com.frequencia-insper"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
security delete-generic-password -s insper-aonline >/dev/null 2>&1

echo "Removido. A pasta ~/Frequencia Insper ficou; pode apagar se quiser."
