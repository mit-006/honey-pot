FROM nginx:alpine

# Remove the default Nginx website configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy frontend static files
COPY frontend/ /usr/share/nginx/html/

# Allow Nginx to read files and traverse directories
RUN chmod -R a+rX /usr/share/nginx/html

# Copy custom Nginx configuration
COPY deploy/nginx/atlas.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
