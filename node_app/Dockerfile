FROM node:18-alpine

WORKDIR /app

# Create a non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy package.json and package-lock.json first to leverage caching
COPY package.json ./
# If you have a package-lock.json, copy it too:
# COPY package-lock.json ./

RUN npm install

# Copy the rest of the application code
COPY . .

RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 3000
CMD ["node", "server.js"]