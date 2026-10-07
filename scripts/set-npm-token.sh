#!/usr/bin/env bash
# Guarda un token de npm de forma segura (la entrada no se muestra ni queda en el historial).
#   bash scripts/set-npm-token.sh
# 1) lo escribe en ~/.npmrc  2) opcionalmente lo sube como secreto NPM_TOKEN a GitHub.
set -euo pipefail

echo "Pega tu token de npm (no se vera al escribir) y pulsa Enter:"
read -rs TOKEN
echo
[[ "$TOKEN" == npm_* ]] || { echo "El token debe empezar por 'npm_'. Abortado."; exit 1; }

NPMRC="$HOME/.npmrc"
touch "$NPMRC"; chmod 600 "$NPMRC"
# Quita cualquier token anterior del registro y agrega el nuevo.
grep -v '^//registry.npmjs.org/:_authToken=' "$NPMRC" > "$NPMRC.tmp" || true
printf '//registry.npmjs.org/:_authToken=%s\n' "$TOKEN" >> "$NPMRC.tmp"
mv "$NPMRC.tmp" "$NPMRC"; chmod 600 "$NPMRC"
echo "✔ Token guardado en ~/.npmrc"

if npm whoami >/dev/null 2>&1; then
  echo "✔ npm te reconoce como: $(npm whoami)"
else
  echo "✖ npm no acepta el token. Revisa que no haya expirado."; exit 1
fi

read -rp "¿Subirlo tambien como secreto NPM_TOKEN al repo de GitHub? [s/N] " yn
if [[ "$yn" =~ ^[sS]$ ]]; then
  printf '%s' "$TOKEN" | gh secret set NPM_TOKEN --repo AndreyMartinez/sqli-guard
  echo "✔ Secreto NPM_TOKEN actualizado en GitHub"
fi
unset TOKEN
echo "Listo. Ahora publica con:  npm publish --access public"
