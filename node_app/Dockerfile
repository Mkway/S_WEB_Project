FROM node:18-alpine

WORKDIR /app

# Install Java and wget for ysoserial
RUN apk add --no-cache openjdk11-jre-headless wget

# Download ysoserial
RUN wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -O /usr/local/bin/ysoserial.jar

# Create a non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Create vulnerable Java files directory
RUN mkdir -p /app/java-payloads && chown -R appuser:appgroup /app

# Copy package.json and package-lock.json first to leverage caching
COPY package.json ./
# If you have a package-lock.json, copy it too:
# COPY package-lock.json ./

# Install npm dependencies with verbose output for debugging
RUN npm install --verbose && npm list

# Copy the rest of the application code
COPY . .

RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 3000
CMD ["node", "server.js"]