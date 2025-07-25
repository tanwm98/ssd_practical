FROM node:24-alpine

RUN addgroup -S appgroup \
 && adduser -S appuser -G appgroup

RUN mkdir -p /home/appuser/app \
 && chown appuser:appgroup /home/appuser/app
WORKDIR /home/appuser/app

COPY --chown=appuser:appgroup package*.json ./

USER appuser

RUN npm install --ignore-scripts

COPY --chown=appuser:appgroup . .

# Set read-only permissions after all modifications are done
RUN chmod 444 package*.json && \
    find src/ public/ -type f -exec chmod 444 {} \; 2>/dev/null || true

EXPOSE 3000
CMD ["npm", "start"]