FROM node:22-alpine AS build

WORKDIR /workspace/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit
COPY web/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/web/dist /usr/share/nginx/html

EXPOSE 8080
