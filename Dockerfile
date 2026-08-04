FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

# La carpeta data/ guarda la base de datos (db.json). En Railway, monta un
# Railway Volume en /app/data desde la configuración del servicio para que
# los datos no se pierdan al reiniciar el contenedor (el VOLUME de Docker no
# está soportado en Railway).
RUN mkdir -p /app/data

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
