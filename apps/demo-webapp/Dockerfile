FROM nginx:1.27-alpine

RUN mkdir -p /usr/share/nginx/html /etc/nginx/conf.d /var/log/nginx \
    && rm -f /var/log/nginx/access.log /var/log/nginx/error.log \
    && touch /var/log/nginx/access.log /var/log/nginx/error.log

COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY app/index.html /usr/share/nginx/html/index.html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]