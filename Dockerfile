FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

# La carpeta data/ guarda la base de datos (db.json). Monta un volumen aqui
# en produccion para que los datos no se pierdan al reiniciar el contenedor.
RUN mkdir -p /app/data
VOLUME ["/app/data"]

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
