# Use official Node.js Alpine image
FROM node:22-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json yarn.lock ./

# Install dependencies
RUN yarn install --frozen-lockfile

# Copy all project files
COPY . .

# Expose the port (default to 80)
EXPOSE ${HONEYPOT_PORT:-80}

# Start the application
CMD ["node", "index.js"]