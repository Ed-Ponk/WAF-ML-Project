# Usamos la base de Nginx
FROM nginx:alpine

# Eliminamos la configuración por defecto para que no choque con la tuya
RUN rm /etc/nginx/conf.d/default.conf

# Copiamos tu archivo de configuración al contenedor
COPY default.conf /etc/nginx/conf.d/default.conf


COPY 403.html /usr/share/nginx/html/403.html