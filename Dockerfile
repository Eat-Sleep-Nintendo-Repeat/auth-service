FROM node

# Timezone Stuff
RUN apt-get install -y tzdata
ENV TZ Europe/Berlin

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY . .

#TAEFIK CONFIG
LABEL traefik.enable="true" \
      traefik.http.routers.esnr-auth.entrypoints="websecure" \
      traefik.http.routers.esnr-auth.rule="Host(`eat-sleep-nintendo-repeat.eu`) && PathPrefix(`/api/auth`)" \
      traefik.http.middlewares.esnr-auth-stripprefix.stripprefix.prefixes="/api/auth" \
      traefik.http.routers.esnr-auth.middlewares="esnr-auth-stripprefix" \
      traefik.port="7872" \
      traefik.http.routers.esnr-auth.tls.certresolver="letsencrypt"

EXPOSE 7872
CMD [ "node", "index.js" ]
