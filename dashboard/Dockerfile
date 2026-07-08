# ── Stage 1: Dependencias y Compilación ─────────────────────────────────
FROM node:18-alpine AS builder
WORKDIR /app

# Instalar dependencias necesarias para compilar módulos de Node si hicieran falta
RUN apk add --no-cache libc6-compat

# Copiar configuración de dependencias
COPY package.json ./
RUN npm install

# Copiar el resto del código y compilar la app Next.js
COPY . .
RUN npm run build

# ── Stage 2: Entorno de Ejecución Autónomo (Standalone) ─────────────────
FROM node:18-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# El modo standalone compila el servidor Next.js en un ejecutable node nativo muy eficiente
COPY --from=builder /app/package.json ./
COPY --from=builder /app/next.config.js ./
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
# pdfkit necesita sus archivos de fuente (.afm) accesibles desde el bundle compilado
COPY --from=builder /app/node_modules/pdfkit/js/data/ ./.next/server/chunks/data/

EXPOSE 3000

CMD ["node", "server.js"]
