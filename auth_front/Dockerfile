FROM nginx:alpine
# Удаляем стандартный конфиг
RUN rm /etc/nginx/conf.d/default.conf
# Копируем наш конфиг
COPY nginx.conf /etc/nginx/conf.d
# Копируем статику
COPY . /usr/share/nginx/html
EXPOSE 80