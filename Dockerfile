FROM node:24-alpine

RUN addgroup -S appgroup \
 && adduser -S appuser -G appgroup

# 3. Create and switch to the application directory owned by our new user
RUN mkdir -p /home/appuser/app \
 && chown appuser:appgroup /home/appuser/app
WORKDIR /home/appuser/app

COPY --chown=appuser:appgroup package*.json ./

USER appuser

RUN npm install --ignore-scripts

COPY --chown=appuser:appgroup . .

EXPOSE 3000
CMD ["npm", "start"]
