# =============================================================================
# DomainRecon - Frontend Dockerfile
# =============================================================================
# Serveur nginx pour les fichiers statiques
# =============================================================================

FROM nginx:alpine

# Copie de la configuration nginx personnalisée
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copie des fichiers statiques
COPY index.html /usr/share/nginx/html/

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
